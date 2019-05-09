/**@file
 * This header file is part of the  I/O library; it contains the C++ interface
 * for the system Bluetooth RFCOMM socket.
 *
 * @see lely/io2/sys/rfcomm.h
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

#ifndef LELY_IO2_SYS_RFCOMM_HPP_
#define LELY_IO2_SYS_RFCOMM_HPP_

#include <lely/io2/sys/rfcomm.h>
#include <lely/io2/rfcomm.hpp>

#include <utility>

namespace lely {
namespace io {

/// A Bluetooth RFCOMM server.
class RfcommServer : public RfcommServerBase {
 public:
  using handle_type = io_rfcomm_handle_t;

  /// @see io_rfcomm_srv_create()
  RfcommServer(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), RfcommServerBase(io_rfcomm_srv_create(poll, exec)) {
    if (!rfcomm_srv) util::throw_errc("RfcommServer");
    dev = io_rfcomm_srv_get_dev(rfcomm_srv);
  }

  RfcommServer(const RfcommServer&) = delete;

  RfcommServer(RfcommServer&& other) noexcept
      : Device(other.dev), RfcommServerBase(other.rfcomm_srv) {
    other.rfcomm_srv = nullptr;
    other.sock_stream_srv = nullptr;
    other.sock = nullptr;
    other.dev = nullptr;
  }

  RfcommServer& operator=(const RfcommServer&) = delete;

  RfcommServer&
  operator=(RfcommServer&& other) noexcept {
    using ::std::swap;
    swap(rfcomm_srv, other.rfcomm_srv);
    swap(sock_stream_srv, other.sock_stream_srv);
    swap(sock, other.sock);
    swap(dev, other.dev);
    return *this;
  }

  /// @see io_rfcomm_srv_destroy()
  ~RfcommServer() { io_rfcomm_srv_destroy(*this); }

  /// @see io_rfcomm_srv_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_rfcomm_srv_get_handle(*this);
  }

  /// @see io_rfcomm_srv_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_rfcomm_srv_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_rfcomm_srv_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }

  /// @see io_rfcomm_srv_release()
  handle_type
  release() noexcept {
    return io_rfcomm_srv_release(*this);
  }
};

/// A Bluetooth RFCOMM socket.
class Rfcomm : public RfcommBase {
 public:
  using handle_type = io_rfcomm_handle_t;

  /// @see io_rfcomm_create()
  Rfcomm(io_poll_t* poll, ev_exec_t* exec)
      : Device(nullptr), RfcommBase(io_rfcomm_create(poll, exec)) {
    if (!rfcomm) util::throw_errc("Rfcomm");
    dev = io_rfcomm_get_dev(rfcomm);
  }

  Rfcomm(const Rfcomm&) = delete;

  Rfcomm(Rfcomm&& other) noexcept
      : Device(other.dev), RfcommBase(other.rfcomm) {
    other.rfcomm = nullptr;
    other.sock_stream = nullptr;
    other.stream = nullptr;
    other.sock = nullptr;
    other.SocketBase::dev = nullptr;
    other.StreamBase::dev = nullptr;
  }

  Rfcomm& operator=(const Rfcomm&) = delete;

  Rfcomm&
  operator=(Rfcomm&& other) noexcept {
    using ::std::swap;
    swap(rfcomm, other.rfcomm);
    swap(sock_stream, other.sock_stream);
    swap(stream, other.stream);
    swap(sock, other.sock);
    swap(SocketBase::dev, other.SocketBase::dev);
    swap(StreamBase::dev, other.StreamBase::dev);
    return *this;
  }

  /// @see io_rfcomm_destroy()
  ~Rfcomm() { io_rfcomm_destroy(*this); }

  /// @see io_rfcomm_get_handle()
  handle_type
  get_handle() const noexcept {
    return io_rfcomm_get_handle(*this);
  }

  /// @see io_rfcomm_assign()
  void
  assign(handle_type fd, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_rfcomm_assign(*this, fd))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_rfcomm_assign()
  void
  assign(handle_type fd) {
    ::std::error_code ec;
    assign(fd, ec);
    if (ec) throw ::std::system_error(ec, "assign");
  }
  /// @see io_rfcomm_release()
  handle_type
  release() noexcept {
    return io_rfcomm_release(*this);
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SYS_RFCOMM_HPP_
