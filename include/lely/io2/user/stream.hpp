/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the user-defined stream.
 *
 * @see lely/io2/user/stream.h
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

#ifndef LELY_IO2_USER_STREAM_HPP_
#define LELY_IO2_USER_STREAM_HPP_

#include <lely/io2/user/stream.h>
#include <lely/io2/stream.hpp>

#include <utility>

namespace lely {
namespace io {

/// A user-defined stream.
class UserStream : public StreamBase {
 public:
  /// @see io_user_stream_create()
  UserStream(io_ctx_t* ctx, ev_exec_t* exec, size_t rxlen = 0,
             int txtimeo = 0, io_user_stream_write_t* func = nullptr,
             void* arg = nullptr)
      : StreamBase(
            io_user_stream_create(ctx, exec, rxlen, txtimeo, func, arg)) {
    if (!stream) util::throw_errc("UserStream");
  }

  UserStream(const UserStream&) = delete;

  UserStream(UserStream&& other) noexcept : StreamBase(other.stream) {
    other.stream = nullptr;
    other.dev = nullptr;
  }

  UserStream& operator=(const UserStream&) = delete;

  UserStream&
  operator=(UserStream&& other) noexcept {
    using ::std::swap;
    swap(stream, other.stream);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_user_stream_destroy()
  ~UserStream() { io_user_stream_destroy(*this); }

  /// @see io_user_stream_on_read()
  bool
  on_read(const ConstBuffer& buffer) noexcept {
    return io_user_stream_on_read(*this, buffer.data(), buffer.size()) != 0;
  }

  /// @see io_user_stream_on_read()
  bool
  on_eof() noexcept {
    return io_user_stream_on_read(*this, nullptr, 0) != 0;
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_USER_STREAM_HPP_
