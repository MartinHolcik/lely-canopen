/**@file
 * This header file is part of the  I/O library; it contains the C++ interface
 * for the system UDP socket.
 *
 * @see lely/io2/sys/udp.h
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

#ifndef LELY_IO2_SYS_UDP_HPP_
#define LELY_IO2_SYS_UDP_HPP_

#include <lely/io2/sys/udp.h>
#include <lely/io2/udp.hpp>

#include <utility>

namespace lely {
namespace io {

/// A UDP socket.
class Udp : public UdpBase {
 public:
  using handle_type = io_udp_handle_t;

  /// @see io_udp_create()
  Udp(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), UdpBase(io_udp_create(poll, exec)) {
    if (!udp) util::throw_errc("Udp");
    dev = io_udp_get_dev(udp);
  }

  Udp(const Udp&) = delete;

  Udp(Udp&& other) noexcept : Device(other.dev), UdpBase(other.udp) {
    other.udp = nullptr;
    other.sock_dgram = nullptr;
    other.sock = nullptr;
    other.dev = nullptr;
  }

  Udp& operator=(const Udp&) = delete;

  Udp&
  operator=(Udp&& other) noexcept {
    using ::std::swap;
    swap(udp, other.udp);
    swap(sock_dgram, other.sock_dgram);
    swap(sock, other.sock);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_udp_destroy()
  ~Udp() { io_udp_destroy(*this); }

  /// @see io_udp_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_udp_get_handle(*this);
  }

  /// @see io_udp_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_udp_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_udp_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }

  /// @see io_udp_release()
  handle_type
  release() noexcept {
    return io_udp_release(*this);
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SYS_UDP_HPP_
