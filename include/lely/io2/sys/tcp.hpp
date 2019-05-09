/**@file
 * This header file is part of the  I/O library; it contains the C++ interface
 * for the system TCP socket.
 *
 * @see lely/io2/sys/tcp.h
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

#ifndef LELY_IO2_SYS_TCP_HPP_
#define LELY_IO2_SYS_TCP_HPP_

#include <lely/io2/sys/tcp.h>
#include <lely/io2/tcp.hpp>

#include <utility>

namespace lely {
namespace io {

/// A TCP server.
class TcpServer : public TcpServerBase {
 public:
  using handle_type = io_tcp_handle_t;

  /// @see io_tcp_srv_create()
  TcpServer(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), TcpServerBase(io_tcp_srv_create(poll, exec)) {
    if (!tcp_srv) util::throw_errc("TcpServer");
  }

  TcpServer(const TcpServer&) = delete;

  TcpServer(TcpServer&& other) noexcept
      : Device(other.dev), TcpServerBase(other.tcp_srv) {
    other.tcp_srv = nullptr;
    other.sock_stream_srv = nullptr;
    other.sock = nullptr;
    other.dev = nullptr;
  }

  TcpServer& operator=(const TcpServer&) = delete;

  TcpServer&
  operator=(TcpServer&& other) noexcept {
    using ::std::swap;
    swap(tcp_srv, other.tcp_srv);
    swap(sock_stream_srv, other.sock_stream_srv);
    swap(sock, other.sock);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_tcp_srv_destroy()
  ~TcpServer() { io_tcp_srv_destroy(*this); }

  /// @see io_tcp_srv_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_tcp_srv_get_handle(*this);
  }

  /// @see io_tcp_srv_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_tcp_srv_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_tcp_srv_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }

  /// @see io_tcp_srv_release()
  handle_type
  release() noexcept {
    return io_tcp_srv_release(*this);
  }
};

/// A TCP socket.
class Tcp : public TcpBase {
 public:
  using handle_type = io_tcp_handle_t;

  /// @see io_tcp_create()
  Tcp(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), TcpBase(io_tcp_create(poll, exec)) {
    if (!tcp) util::throw_errc("Tcp");
    dev = io_tcp_get_dev(tcp);
  }

  Tcp(const Tcp&) = delete;

  Tcp(Tcp&& other) noexcept : Device(other.dev), TcpBase(other.tcp) {
    other.tcp = nullptr;
    other.sock_stream = nullptr;
    other.stream = nullptr;
    other.sock = nullptr;
    other.dev = nullptr;
  }

  Tcp& operator=(const Tcp&) = delete;

  Tcp&
  operator=(Tcp&& other) noexcept {
    using ::std::swap;
    swap(tcp, other.tcp);
    swap(sock_stream, other.sock_stream);
    swap(stream, other.stream);
    swap(sock, other.sock);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_tcp_destroy()
  ~Tcp() { io_tcp_destroy(*this); }

  /// @see io_tcp_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_tcp_get_handle(*this);
  }

  /// @see io_tcp_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_tcp_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_tcp_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }

  /// @see io_tcp_release()
  handle_type
  release() noexcept {
    return io_tcp_release(*this);
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SYS_TCP_HPP_
