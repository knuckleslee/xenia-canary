/**
 ******************************************************************************
 * Xenia : Xbox 360 Emulator Research Project                                 *
 ******************************************************************************
 * Copyright 2026 Xenia Canary. All rights reserved.                          *
 * Released under the BSD license - see LICENSE in the root for more details. *
 ******************************************************************************
 */

// LDI exports: block based LZX decompression on top of libmspack's lzxd.

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <mutex>
#include <unordered_map>

#include "xenia/base/logging.h"
#include "xenia/base/math.h"
#include "xenia/kernel/util/shim_utils.h"
#include "xenia/kernel/xboxkrnl/xboxkrnl_private.h"
#include "xenia/xbox.h"

#include "third_party/mspack/lzx.h"
#include "third_party/mspack/mspack.h"

namespace xe {
namespace kernel {
namespace xboxkrnl {

namespace {

constexpr uint32_t kLzxFrameSize = 0x8000;
// Maximum growth of a compressed frame, as in libmspack (CAB_INPUTMAX).
constexpr uint32_t kLzxMaxCompressedFrameSize = kLzxFrameSize + 6144;
// TODO(knuckleslee): Find the error codes the console returns.
constexpr X_STATUS kLdiError = X_STATUS_UNSUCCESSFUL;
constexpr uint32_t kLzxMinWindowBits = 15;
constexpr uint32_t kLzxMaxWindowBits = 21;

// One direction of lzxd I/O: a span of memory that is replaced before every
// call. mspack_system hands these back to the callbacks as mspack_file*.
struct LdiBuffer {
  uint8_t* data;
  size_t size;
  size_t offset;
};

int LdiRead(mspack_file* file, void* buffer, int bytes) {
  auto ldi_buffer = reinterpret_cast<LdiBuffer*>(file);
  const size_t count = std::min(static_cast<size_t>(bytes),
                                ldi_buffer->size - ldi_buffer->offset);
  std::memcpy(buffer, ldi_buffer->data + ldi_buffer->offset, count);
  ldi_buffer->offset += count;
  return static_cast<int>(count);
}

int LdiWrite(mspack_file* file, void* buffer, int bytes) {
  auto ldi_buffer = reinterpret_cast<LdiBuffer*>(file);
  const size_t count = std::min(static_cast<size_t>(bytes),
                                ldi_buffer->size - ldi_buffer->offset);
  std::memcpy(ldi_buffer->data + ldi_buffer->offset, buffer, count);
  ldi_buffer->offset += count;
  return static_cast<int>(count);
}

void* LdiAlloc(mspack_system* system, size_t bytes) {
  return std::calloc(bytes, 1);
}

void LdiFree(void* pointer) { std::free(pointer); }

void LdiCopy(void* source, void* destination, size_t bytes) {
  std::memcpy(destination, source, bytes);
}

void LdiMessage(mspack_file* file, const char* format, ...) {}

class LdiContext {
 public:
  explicit LdiContext(uint32_t window_bits) : window_bits_(window_bits) {
    system_.read = LdiRead;
    system_.write = LdiWrite;
    system_.alloc = LdiAlloc;
    system_.free = LdiFree;
    system_.copy = LdiCopy;
    system_.message = LdiMessage;
    Reset();
  }

  ~LdiContext() { Free(); }

  bool is_valid() const { return stream_ != nullptr; }

  void Reset() {
    Free();
    stream_ = lzxd_init(&system_, reinterpret_cast<mspack_file*>(&input_),
                        reinterpret_cast<mspack_file*>(&output_), window_bits_,
                        0, kLzxFrameSize, 0, 0);
  }

  bool Decompress(uint8_t* source, size_t source_size, uint8_t* destination,
                  uint32_t& destination_size) {
    if (!stream_ || !destination_size || destination_size > kLzxFrameSize) {
      return false;
    }

    input_ = {source, source_size, 0};
    output_ = {destination, destination_size, 0};

    // lzxd reads padding past the end of a frame; drop its buffered input so
    // the next block starts with a clean bit reader.
    stream_->i_ptr = stream_->i_end = stream_->inbuf;
    stream_->bit_buffer = 0;
    stream_->bits_left = 0;
    stream_->input_end = 0;
    lzxd_set_output_length(stream_, stream_->offset + destination_size);

    // Ending exactly on a frame boundary makes lzxd decode the next frame, so
    // decode one byte less first, then the last byte.
    int result = lzxd_decompress(stream_, destination_size - 1);
    if (result == MSPACK_ERR_OK) {
      result = lzxd_decompress(stream_, 1);
    }

    destination_size = static_cast<uint32_t>(output_.offset);
    return result == MSPACK_ERR_OK;
  }

 private:
  void Free() {
    if (stream_) {
      lzxd_free(stream_);
      stream_ = nullptr;
    }
  }

  uint32_t window_bits_;
  mspack_system system_ = {};
  LdiBuffer input_ = {};
  LdiBuffer output_ = {};
  lzxd_stream* stream_ = nullptr;
};

std::mutex g_ldi_mutex;
std::unordered_map<uint32_t, std::unique_ptr<LdiContext>> g_ldi_contexts;
uint32_t g_ldi_next_handle = 1;

// Checks that the first and last byte of a guest range are mapped.
bool IsGuestRangeValid(uint32_t address, uint32_t size) {
  if (!size) {
    return true;
  }
  const uint32_t last_address = address + size - 1;
  return last_address >= address &&
         kernel_memory()->LookupHeap(address) != nullptr &&
         kernel_memory()->LookupHeap(last_address) != nullptr;
}

}  // namespace

dword_result_t LDICreateDecompression_entry(
    lpdword_t max_block_size_ptr, lpdword_t config_ptr, dword_t alloc_callback,
    dword_t free_callback, lpvoid_t unknown_ptr, lpdword_t max_source_size_ptr,
    lpdword_t handle_ptr) {
  if (!max_block_size_ptr || !config_ptr || !handle_ptr) {
    XELOGE(
        "LDICreateDecompression: null pointer (max_block_size_ptr {:08X}, "
        "config_ptr {:08X}, handle_ptr {:08X})",
        max_block_size_ptr.guest_address(), config_ptr.guest_address(),
        handle_ptr.guest_address());
    return kLdiError;
  }

  const uint32_t max_block_size = *max_block_size_ptr;
  if (max_block_size > kLzxFrameSize) {
    XELOGE("LDICreateDecompression: unsupported max block size {:08X}",
           max_block_size);
    return kLdiError;
  }

  const uint32_t window_size = config_ptr[0];
  uint32_t window_bits;
  if (!xe::is_pow2(window_size) ||
      !xe::bit_scan_forward(window_size, &window_bits) ||
      window_bits < kLzxMinWindowBits || window_bits > kLzxMaxWindowBits) {
    XELOGE("LDICreateDecompression: unsupported window size {:08X}",
           window_size);
    return kLdiError;
  }

  auto context = std::make_unique<LdiContext>(window_bits);
  if (!context->is_valid()) {
    XELOGE("LDICreateDecompression: lzxd_init failed for window bits {}",
           window_bits);
    return kLdiError;
  }

  if (max_source_size_ptr) {
    *max_source_size_ptr = kLzxMaxCompressedFrameSize;
  }

  std::lock_guard<std::mutex> lock(g_ldi_mutex);
  const uint32_t handle = g_ldi_next_handle++;
  g_ldi_contexts.emplace(handle, std::move(context));
  *handle_ptr = handle;
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(LDICreateDecompression, kNone, kSketchy);

dword_result_t LDIDecompress_entry(dword_t handle, lpvoid_t source_ptr,
                                   dword_t source_size,
                                   lpvoid_t destination_ptr,
                                   lpdword_t destination_size_ptr) {
  if (!source_ptr || !destination_ptr || !destination_size_ptr) {
    XELOGE(
        "LDIDecompress: null pointer (source_ptr {:08X}, destination_ptr "
        "{:08X}, destination_size_ptr {:08X})",
        source_ptr.guest_address(), destination_ptr.guest_address(),
        destination_size_ptr.guest_address());
    return kLdiError;
  }
  if (!source_size) {
    XELOGE("LDIDecompress: source_size is 0");
    return kLdiError;
  }

  std::lock_guard<std::mutex> lock(g_ldi_mutex);
  auto it = g_ldi_contexts.find(handle);
  if (it == g_ldi_contexts.end()) {
    XELOGE("LDIDecompress: invalid handle {:08X}", handle.value());
    return kLdiError;
  }

  uint32_t destination_size = *destination_size_ptr;
  if (!IsGuestRangeValid(source_ptr.guest_address(), source_size) ||
      !IsGuestRangeValid(destination_ptr.guest_address(), destination_size)) {
    XELOGE(
        "LDIDecompress: invalid range (source {:08X} size {:08X}, destination "
        "{:08X} size {:08X})",
        source_ptr.guest_address(), source_size.value(),
        destination_ptr.guest_address(), destination_size);
    return kLdiError;
  }

  const bool succeeded =
      it->second->Decompress(source_ptr.as<uint8_t*>(), source_size,
                             destination_ptr.as<uint8_t*>(), destination_size);
  *destination_size_ptr = destination_size;
  if (!succeeded) {
    XELOGE("LDIDecompress: failed (source size {}, output size {})",
           source_size.value(), destination_size);
    return kLdiError;
  }
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(LDIDecompress, kNone, kSketchy);

dword_result_t LDIResetDecompression_entry(dword_t handle) {
  std::lock_guard<std::mutex> lock(g_ldi_mutex);
  auto it = g_ldi_contexts.find(handle);
  if (it == g_ldi_contexts.end()) {
    XELOGE("LDIResetDecompression: invalid handle {:08X}", handle.value());
    return kLdiError;
  }

  it->second->Reset();
  if (!it->second->is_valid()) {
    XELOGE("LDIResetDecompression: lzxd_init failed for handle {:08X}",
           handle.value());
    return kLdiError;
  }
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(LDIResetDecompression, kNone, kSketchy);

dword_result_t LDIDestroyDecompression_entry(dword_t handle) {
  std::lock_guard<std::mutex> lock(g_ldi_mutex);
  if (!g_ldi_contexts.erase(handle)) {
    XELOGE("LDIDestroyDecompression: invalid handle {:08X}", handle.value());
    return kLdiError;
  }
  return X_STATUS_SUCCESS;
}
DECLARE_XBOXKRNL_EXPORT1(LDIDestroyDecompression, kNone, kSketchy);

}  // namespace xboxkrnl
}  // namespace kernel
}  // namespace xe

DECLARE_XBOXKRNL_EMPTY_REGISTER_EXPORTS(Ldi);
