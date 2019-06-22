/**@file
 * This header file is part of the  I/O library; it contains the C++ interface
 * for the system serial port.
 *
 * @see lely/io2/sys/serial.h
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

#ifndef LELY_IO2_SYS_SERIAL_HPP_
#define LELY_IO2_SYS_SERIAL_HPP_

#include <lely/io2/sys/serial.h>
#include <lely/io2/serial.hpp>

#include <string>
#include <utility>

namespace lely {
namespace io {

/// A serial port.
class Serial : public SerialBase {
 public:
  using handle_type = io_serial_handle_t;

  /// @see io_serial_create()
  Serial(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), SerialBase(io_serial_create(poll, exec)) {
    if (!serial) util::throw_errc("Serial");
    dev = io_serial_get_dev(serial);
  }

  Serial(const Serial&) = delete;

  Serial(Serial&& other) noexcept
      : Device(other.dev), SerialBase(other.serial) {
    other.serial = nullptr;
    other.dev = nullptr;
  }

  Serial& operator=(const Serial&) = delete;

  Serial&
  operator=(Serial&& other) noexcept {
    using ::std::swap;
    swap(serial, other.serial);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_serial_destroy()
  ~Serial() { io_serial_destroy(*this); }

  /// @see io_serial_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_serial_get_handle(*this);
  }

  /// @see io_serial_open()
  void
  open(const char* filename, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_open(*this, filename))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_open()
  void
  open(const char* filename) {
    ::std::error_code ec;
    open(filename, ec);
    if (ec) throw ::std::system_error(ec, "open");
  }

  /// @see io_serial_open()
  void
  open(const ::std::string& filename, ::std::error_code& ec) noexcept {
    open(filename.c_str(), ec);
  }

  /// @see io_serial_open()
  void
  open(const ::std::string& filename) {
    open(filename.c_str());
  }

  /// @see io_serial_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }

  /// @see io_serial_release()
  handle_type
  release() noexcept {
    return io_serial_release(*this);
  }

  /// @see io_serial_is_open()
  bool
  is_open() const noexcept {
    return io_serial_is_open(*this) != 0;
  }

  /// @see io_serial_close()
  void
  close(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_close(*this))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_close()
  void
  close() {
    ::std::error_code ec;
    close(ec);
    if (ec) throw ::std::system_error(ec, "close");
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SYS_SERIAL_HPP_
