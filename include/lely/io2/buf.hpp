/**@file
 * This header file is part of the I/O library; it contains the C++ I/O buffer
 * declarations.
 *
 * @see lely/io2/buf.h
 *
 * @copyright 2019 Lely Industries N.V.
 *
 * @author J. S. Seldenthuis <jseldenthuis@lely.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef LELY_IO2_BUF_HPP_
#define LELY_IO2_BUF_HPP_

#include <lely/io2/buf.h>

#include <algorithm>
#include <array>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <vector>

#ifndef LELY_IO_MAX_BUFCNT
/**
 * The maximum number of buffers in a single vectored read or write operation
 * that does not incur a heap allocation in the read or write operation.
 */
#define LELY_IO_MAX_BUFCNT 16
#endif

namespace lely {
namespace io {

/// A mutable memory buffer suitable for read operations.
struct Buffer : public io_buf {
  Buffer() noexcept : io_buf IO_BUF_INIT(nullptr, 0) {}

  Buffer(void* p, ::std::size_t n) noexcept : io_buf IO_BUF_INIT(p, n) {}

  /// Returns the base address of the buffer.
  void*
  data() const noexcept {
    return base;
  }

  /// Returns the size (in bytes) of the buffer.
  ::std::size_t
  size() const noexcept {
    return len;
  }
};

inline Buffer
buffer(void* p, ::std::size_t n) noexcept {
  return Buffer(p, n);
}

inline Buffer
buffer(const Buffer& b) noexcept {
  return b;
}

inline Buffer
buffer(const Buffer& b, ::std::size_t n) noexcept {
  return Buffer(b.data(), ::std::min(b.size(), n));
}

template <class T, ::std::size_t N>
inline Buffer
buffer(T (&data)[N]) noexcept {
  return buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, ::std::size_t N>
inline Buffer
buffer(T (&data)[N], ::std::size_t n) noexcept {
  return buffer(buffer(data), n);
}

template <class T, ::std::size_t N>
inline Buffer
buffer(::std::array<T, N>& data) noexcept {
  return buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, ::std::size_t N>
inline Buffer
buffer(::std::array<T, N>& data, ::std::size_t n) noexcept {
  return buffer(buffer(data), n);
}

template <class T, class Allocator>
inline Buffer
buffer(::std::vector<T, Allocator>& data) noexcept {
  return buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, class Allocator>
inline Buffer
buffer(::std::vector<T, Allocator>& data, ::std::size_t n) noexcept {
  return buffer(buffer(data), n);
}

template <class CharT, class Traits, class Allocator>
inline Buffer
buffer(::std::basic_string<CharT, Traits, Allocator>& data) noexcept {
  return buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class CharT, class Traits, class Allocator>
inline Buffer
buffer(::std::basic_string<CharT, Traits, Allocator>& data,
       ::std::size_t n) noexcept {
  return buffer(buffer(data), n);
}

inline const Buffer*
buffer_sequence_begin(const Buffer& b) noexcept {
  return ::std::addressof(b);
}

inline const Buffer*
buffer_sequence_end(const Buffer& b) noexcept {
  return ::std::addressof(b) + 1;
}

template <class T>
inline auto
buffer_sequence_begin(T& t) noexcept -> decltype(t.begin()) {
  return t.begin();
}

template <class T>
inline auto
buffer_sequence_end(T& t) noexcept -> decltype(t.end()) {
  return t.end();
}

namespace detail {

class BufferArray {
 public:
  BufferArray() noexcept {}

  BufferArray(const BufferArray& other)
      : BufferArray(other.begin(), other.end()) {}

  BufferArray&
  operator=(const BufferArray& other) {
    assign(other.begin(), other.end());
    return *this;
  }

  BufferArray(BufferArray&& other) noexcept
      : buf_(other.buf_), bufcnt_(other.bufcnt_) {
    other.buf_ = nullptr;
    if (!buf_) {
      for (int i = 0; i < bufcnt_; i++) sbuf_[i] = ::std::move(other.sbuf_[i]);
    }
  }

  BufferArray&
  operator=(BufferArray&& other) {
    using ::std::swap;
    swap(buf_, other.buf_);
    swap(bufcnt_, other.bufcnt_);
    if (!buf_) {
      if (!other.buf_) {
        for (int i = 0; i < ::std::max(bufcnt_, other.bufcnt_); i++)
          swap(sbuf_[i], other.sbuf_[i]);
      } else {
        for (int i = 0; i < bufcnt_; i++)
          sbuf_[i] = ::std::move(other.sbuf_[i]);
      }
    } else if (!other.buf_) {
      for (int i = 0; i < other.bufcnt_; i++)
        other.sbuf_[i] = ::std::move(sbuf_[i]);
    }
    return *this;
  }

  template <class BufferSequence>
  BufferArray(BufferSequence& s) {
    *this = s;
  }

  template <class BufferSequence>
  BufferArray&
  operator=(BufferSequence& buffers) {
    assign(buffer_sequence_begin(buffers), buffer_sequence_end(buffers));
    return *this;
  }

  template <class InputIt>
  BufferArray(InputIt first, InputIt last) {
    assign(first, last);
  }

  ~BufferArray() noexcept { delete[] buf_; }

  const Buffer*
  begin() const noexcept {
    return buf_ ? buf_ : sbuf_;
  }

  const Buffer*
  end() const noexcept {
    return begin() + bufcnt_;
  }

  const io_buf*
  buf() const noexcept {
    return begin();
  }

  int
  bufcnt() const noexcept {
    return bufcnt_;
  }

  template <class InputIt>
  void
  assign(InputIt first, InputIt last) {
    auto n = ::std::distance(first, last);
    if (n != bufcnt_) {
      delete[] buf_;
      buf_ = nullptr;
      if (n > LELY_IO_MAX_BUFCNT) buf_ = new Buffer[n];
      bufcnt_ = n;
    }
    Buffer* buf = buf_ ? buf_ : sbuf_;
    for (int i = 0; i < n; i++, ++first) buf[i] = buffer(*first);
  }

 private:
  Buffer* buf_{nullptr};
  int bufcnt_{0};
  Buffer sbuf_[LELY_IO_MAX_BUFCNT];
};

}  // namespace detail

/// A constant memory buffer suitable for write operations.
struct ConstBuffer : public io_buf {
  ConstBuffer() noexcept : io_buf IO_BUF_INIT(nullptr, 0) {}

  ConstBuffer(const void* p, ::std::size_t n) noexcept
      : io_buf IO_BUF_INIT(p, n) {}

  ConstBuffer(const Buffer& b) noexcept : ConstBuffer(b.data(), b.size()) {}

  /// Returns the base address of the buffer.
  const void*
  data() const noexcept {
    return base;
  }

  /// Returns the size (in bytes) of the buffer.
  ::std::size_t
  size() const noexcept {
    return len;
  }
};

inline ConstBuffer
const_buffer(const void* p, ::std::size_t n) noexcept {
  return ConstBuffer(p, n);
}

inline ConstBuffer
const_buffer(const ConstBuffer& b) noexcept {
  return b;
}

inline ConstBuffer
const_buffer(const ConstBuffer& b, ::std::size_t n) noexcept {
  return ConstBuffer(b.data(), ::std::min(b.size(), n));
}

template <class T, ::std::size_t N>
inline ConstBuffer
const_buffer(const T (&data)[N]) noexcept {
  return const_buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, ::std::size_t N>
inline ConstBuffer
const_buffer(const T (&data)[N], ::std::size_t n) noexcept {
  return const_buffer(const_buffer(data), n);
}

template <class T, ::std::size_t N>
inline ConstBuffer
const_buffer(const ::std::array<T, N>& data) noexcept {
  return const_buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, ::std::size_t N>
inline ConstBuffer
const_buffer(const ::std::array<T, N>& data, ::std::size_t n) noexcept {
  return const_buffer(const_buffer(data), n);
}

template <class T, class Allocator>
inline ConstBuffer
const_buffer(const ::std::vector<T, Allocator>& data) noexcept {
  return const_buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class T, class Allocator>
inline ConstBuffer
const_buffer(const ::std::vector<T, Allocator>& data,
             ::std::size_t n) noexcept {
  return const_buffer(const_buffer(data), n);
}

template <class CharT, class Traits, class Allocator>
inline ConstBuffer
const_buffer(
    const ::std::basic_string<CharT, Traits, Allocator>& data) noexcept {
  return const_buffer(
      begin(data) != end(data) ? ::std::addressof(*begin(data)) : nullptr,
      (end(data) - begin(data)) * sizeof(*begin(data)));
}

template <class CharT, class Traits, class Allocator>
inline ConstBuffer
const_buffer(const ::std::basic_string<CharT, Traits, Allocator>& data,
             ::std::size_t n) noexcept {
  return const_buffer(const_buffer(data), n);
}

inline const ConstBuffer*
const_buffer_sequence_begin(const ConstBuffer& b) noexcept {
  return ::std::addressof(b);
}

inline const ConstBuffer*
const_buffer_sequence_end(const ConstBuffer& b) noexcept {
  return ::std::addressof(b) + 1;
}

template <class T>
inline auto
const_buffer_sequence_begin(T& t) noexcept -> decltype(t.begin()) {
  return t.begin();
}

template <class T>
inline auto
const_buffer_sequence_end(T& t) noexcept -> decltype(t.end()) {
  return t.end();
}

namespace detail {

class ConstBufferArray {
 public:
  ConstBufferArray() noexcept {}

  ConstBufferArray(const ConstBufferArray& other)
      : ConstBufferArray(other.begin(), other.end()) {}

  ConstBufferArray&
  operator=(const ConstBufferArray& other) {
    assign(other.begin(), other.end());
    return *this;
  }

  ConstBufferArray(ConstBufferArray&& other) noexcept
      : buf_(other.buf_), bufcnt_(other.bufcnt_) {
    other.buf_ = nullptr;
    if (!buf_) {
      for (int i = 0; i < bufcnt_; i++) sbuf_[i] = ::std::move(other.sbuf_[i]);
    }
  }

  ConstBufferArray&
  operator=(ConstBufferArray&& other) {
    using ::std::swap;
    swap(buf_, other.buf_);
    swap(bufcnt_, other.bufcnt_);
    if (!buf_) {
      if (!other.buf_) {
        for (int i = 0; i < ::std::max(bufcnt_, other.bufcnt_); i++)
          swap(sbuf_[i], other.sbuf_[i]);
      } else {
        for (int i = 0; i < bufcnt_; i++)
          sbuf_[i] = ::std::move(other.sbuf_[i]);
      }
    } else if (!other.buf_) {
      for (int i = 0; i < other.bufcnt_; i++)
        other.sbuf_[i] = ::std::move(sbuf_[i]);
    }
    return *this;
  }

  template <class ConstBufferSequence>
  ConstBufferArray(ConstBufferSequence& s) {
    *this = s;
  }

  template <class ConstBufferSequence>
  ConstBufferArray&
  operator=(ConstBufferSequence& buffers) {
    assign(const_buffer_sequence_begin(buffers),
           const_buffer_sequence_end(buffers));
    return *this;
  }

  template <class InputIt>
  ConstBufferArray(InputIt first, InputIt last) {
    assign(first, last);
  }

  ~ConstBufferArray() noexcept { delete[] buf_; }

  const ConstBuffer*
  begin() const noexcept {
    return buf_ ? buf_ : sbuf_;
  }

  const ConstBuffer*
  end() const noexcept {
    return begin() + bufcnt_;
  }

  const io_buf*
  buf() const noexcept {
    return begin();
  }

  int
  bufcnt() const noexcept {
    return bufcnt_;
  }

  template <class InputIt>
  void
  assign(InputIt first, InputIt last) {
    auto n = ::std::distance(first, last);
    if (n != bufcnt_) {
      delete[] buf_;
      buf_ = nullptr;
      if (n > LELY_IO_MAX_BUFCNT) buf_ = new ConstBuffer[n];
      bufcnt_ = n;
    }
    ConstBuffer* buf = buf_ ? buf_ : sbuf_;
    for (int i = 0; i < n; i++, ++first) buf[i] = const_buffer(*first);
  }

 private:
  ConstBuffer* buf_{nullptr};
  int bufcnt_{0};
  ConstBuffer sbuf_[LELY_IO_MAX_BUFCNT];
};

}  // namespace detail

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_BUF_HPP_
