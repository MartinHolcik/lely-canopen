/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract UDP socket.
 *
 * @see lely/io2/udp.h
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

#ifndef LELY_IO2_UDP_HPP_
#define LELY_IO2_UDP_HPP_

#include <lely/io2/endp.hpp>
#include <lely/io2/ipv4.hpp>
#include <lely/io2/ipv6.hpp>
#include <lely/io2/sock_dgram.hpp>
#include <lely/io2/udp.h>

#include <string>

namespace lely {
namespace io {

template <>
inline const io_endp_ipv4_udp*
endpoint_cast<io_endp_ipv4_udp>(const io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV4 || endp->protocol != IO_IPPROTO_UDP)
    throw bad_endpoint_cast();
  return reinterpret_cast<const io_endp_ipv4_udp*>(endp);
}

template <>
inline io_endp_ipv4_udp*
endpoint_cast<io_endp_ipv4_udp>(io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV4 || endp->protocol != IO_IPPROTO_UDP)
    throw bad_endpoint_cast();
  return reinterpret_cast<io_endp_ipv4_udp*>(endp);
}

/// An IPv4 UDP endpoint.
class Ipv4UdpEndpoint : public io_endp_ipv4_udp {
 public:
  using port_type = uint_least16_t;

  Ipv4UdpEndpoint() noexcept : io_endp_ipv4_udp IO_ENDP_IPV4_UDP_INIT(this) {}

  Ipv4UdpEndpoint(const io_endp_ipv4_udp& endp) noexcept
      : io_endp_ipv4_udp(endp) {
    addr = address();
  }

  Ipv4UdpEndpoint&
  operator=(const io_endp_ipv4_udp& endp) noexcept {
    io_endp_ipv4_udp::operator=(endp);
    addr = address();
    return *this;
  }

  Ipv4UdpEndpoint(const Ipv4UdpEndpoint& endp) noexcept
      : Ipv4UdpEndpoint(static_cast<const io_endp_ipv4_udp&>(endp)) {}

  Ipv4UdpEndpoint&
  operator=(const Ipv4UdpEndpoint& endp) noexcept {
    return *this = static_cast<const io_endp_ipv4_udp&>(endp);
  }

  Ipv4UdpEndpoint(const io_endp& endp)
      : Ipv4UdpEndpoint(endpoint_cast<const io_endp_ipv4_udp&>(endp)) {}

  Ipv4UdpEndpoint&
  operator=(const io_endp& endp) {
    return *this = endpoint_cast<const io_endp_ipv4_udp&>(endp);
  }

  Ipv4UdpEndpoint(const io_addr_ipv4& addr, port_type port_ = 0) noexcept
      : Ipv4UdpEndpoint() {
    address() = addr;
    port = port_;
  }

  Ipv4UdpEndpoint(const char* str, port_type port)
      : Ipv4UdpEndpoint(Ipv4Address(str), port) {}

  Ipv4UdpEndpoint(const ::std::string& str, port_type port)
      : Ipv4UdpEndpoint(Ipv4Address(str), port) {}

  /// @see make_ipv4_udp_endpoint()
  Ipv4UdpEndpoint(const char* str) { *this = str; }

  /// @see make_ipv4_udp_endpoint()
  Ipv4UdpEndpoint& operator=(const char* str);

  /// @see make_ipv4_udp_endpoint()
  Ipv4UdpEndpoint(const ::std::string& str) { *this = str; }

  /// @see make_ipv4_udp_endpoint()
  Ipv4UdpEndpoint& operator=(const ::std::string& str);

  operator io_endp*() noexcept { return reinterpret_cast<io_endp*>(this); }

  operator const io_endp*() const noexcept {
    return reinterpret_cast<const io_endp*>(this);
  }

  Ipv4Address&
  address() noexcept {
    return *static_cast<Ipv4Address*>(&ipv4);
  }

  const Ipv4Address&
  address() const noexcept {
    return *static_cast<const Ipv4Address*>(&ipv4);
  }

  /// @see io_endp_ipv4_udp_to_string()
  ::std::string
  to_string() const {
    char str[IO_ENDP_IPV4_UDP_STRLEN] = {0};
    io_endp_ipv4_udp_to_string(this, str);
    return ::std::string{str};
  }
};

/// @see io_endp_ipv4_udp_set_from_string()
inline Ipv4UdpEndpoint
make_ipv4_udp_endpoint(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv4UdpEndpoint endp;
  ec.clear();
  if (io_endp_ipv4_udp_set_from_string(&endp, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return endp;
}

/// @see io_endp_ipv4_udp_set_from_string()
inline Ipv4UdpEndpoint
make_ipv4_udp_endpoint(const char* str) {
  ::std::error_code ec;
  auto endp = make_ipv4_udp_endpoint(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv4_udp_endpoint");
  return endp;
}

/// @see io_endp_ipv4_udp_set_from_string()
inline Ipv4UdpEndpoint
make_ipv4_udp_endpoint(const ::std::string& str,
                       ::std::error_code& ec) noexcept {
  return make_ipv4_udp_endpoint(str.c_str(), ec);
}

/// @see io_endp_ipv4_udp_set_from_string()
inline Ipv4UdpEndpoint
make_ipv4_udp_endpoint(const ::std::string& str) {
  return make_ipv4_udp_endpoint(str.c_str());
}

inline Ipv4UdpEndpoint&
Ipv4UdpEndpoint::operator=(const char* str) {
  return *this = make_ipv4_udp_endpoint(str);
}

inline Ipv4UdpEndpoint&
Ipv4UdpEndpoint::operator=(const ::std::string& str) {
  return *this = make_ipv4_udp_endpoint(str);
}

template <>
inline const io_endp_ipv6_udp*
endpoint_cast<io_endp_ipv6_udp>(const io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV6 || endp->protocol != IO_IPPROTO_UDP)
    throw bad_endpoint_cast();
  return reinterpret_cast<const io_endp_ipv6_udp*>(endp);
}

template <>
inline io_endp_ipv6_udp*
endpoint_cast<io_endp_ipv6_udp>(io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV6 || endp->protocol != IO_IPPROTO_UDP)
    throw bad_endpoint_cast();
  return reinterpret_cast<io_endp_ipv6_udp*>(endp);
}

/// An IPv6 UDP endpoint.
class Ipv6UdpEndpoint : public io_endp_ipv6_udp {
 public:
  using port_type = uint_least16_t;

  Ipv6UdpEndpoint() noexcept : io_endp_ipv6_udp IO_ENDP_IPV6_UDP_INIT(this) {}

  Ipv6UdpEndpoint(const io_endp_ipv6_udp& endp) noexcept
      : io_endp_ipv6_udp(endp) {
    addr = address();
  }

  Ipv6UdpEndpoint&
  operator=(const io_endp_ipv6_udp& endp) noexcept {
    io_endp_ipv6_udp::operator=(endp);
    addr = address();
    return *this;
  }

  Ipv6UdpEndpoint(const Ipv6UdpEndpoint& endp) noexcept
      : Ipv6UdpEndpoint(static_cast<const io_endp_ipv6_udp&>(endp)) {}

  Ipv6UdpEndpoint&
  operator=(const Ipv6UdpEndpoint& endp) noexcept {
    return *this = static_cast<const io_endp_ipv6_udp&>(endp);
  }

  Ipv6UdpEndpoint(const io_endp& endp)
      : Ipv6UdpEndpoint(endpoint_cast<const io_endp_ipv6_udp&>(endp)) {}

  Ipv6UdpEndpoint&
  operator=(const io_endp& endp) {
    return *this = endpoint_cast<const io_endp_ipv6_udp&>(endp);
  }

  Ipv6UdpEndpoint(const io_addr_ipv6& addr, port_type port_ = 0) noexcept
      : Ipv6UdpEndpoint() {
    address() = addr;
    port = port_;
  }

  Ipv6UdpEndpoint(const char* str, port_type port)
      : Ipv6UdpEndpoint(Ipv6Address(str), port) {}

  Ipv6UdpEndpoint(const ::std::string& str, port_type port)
      : Ipv6UdpEndpoint(Ipv6Address(str), port) {}

  /// @see make_ipv6_udp_endpoint()
  Ipv6UdpEndpoint(const char* str) { *this = str; }

  /// @see make_ipv6_udp_endpoint()
  Ipv6UdpEndpoint& operator=(const char* str);

  /// @see make_ipv6_udp_endpoint()
  Ipv6UdpEndpoint(const ::std::string& str) { *this = str; }

  /// @see make_ipv6_udp_endpoint()
  Ipv6UdpEndpoint& operator=(const ::std::string& str);

  operator io_endp*() noexcept { return reinterpret_cast<io_endp*>(this); }

  operator const io_endp*() const noexcept {
    return reinterpret_cast<const io_endp*>(this);
  }

  Ipv6Address&
  address() noexcept {
    return *static_cast<Ipv6Address*>(&ipv6);
  }

  const Ipv6Address&
  address() const noexcept {
    return *static_cast<const Ipv6Address*>(&ipv6);
  }

  /// @see io_endp_ipv6_udp_to_string()
  ::std::string
  to_string() const {
    char str[IO_ENDP_IPV6_UDP_STRLEN] = {0};
    io_endp_ipv6_udp_to_string(this, str);
    return ::std::string{str};
  }
};

/// @see io_endp_ipv6_udp_set_from_string()
inline Ipv6UdpEndpoint
make_ipv6_udp_endpoint(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv6UdpEndpoint endp;
  ec.clear();
  if (io_endp_ipv6_udp_set_from_string(&endp, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return endp;
}

/// @see io_endp_ipv6_udp_set_from_string()
inline Ipv6UdpEndpoint
make_ipv6_udp_endpoint(const char* str) {
  ::std::error_code ec;
  auto endp = make_ipv6_udp_endpoint(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv6_udp_endpoint");
  return endp;
}

/// @see io_endp_ipv6_udp_set_from_string()
inline Ipv6UdpEndpoint
make_ipv6_udp_endpoint(const ::std::string& str,
                       ::std::error_code& ec) noexcept {
  return make_ipv6_udp_endpoint(str.c_str(), ec);
}

/// @see io_endp_ipv6_udp_set_from_string()
inline Ipv6UdpEndpoint
make_ipv6_udp_endpoint(const ::std::string& str) {
  return make_ipv6_udp_endpoint(str.c_str());
}

inline Ipv6UdpEndpoint&
Ipv6UdpEndpoint::operator=(const char* str) {
  return *this = make_ipv6_udp_endpoint(str);
}

inline Ipv6UdpEndpoint&
Ipv6UdpEndpoint::operator=(const ::std::string& str) {
  return *this = make_ipv6_udp_endpoint(str);
}

/// A reference to a UDP socket. This class is a wrapper around `#io_udp_t*`.
class UdpBase : public DatagramSocketBase {
 public:
  using Device::operator io_dev_t*;
  using SocketBase::operator io_sock_t*;
  using DatagramSocketBase::operator io_sock_dgram_t*;

  explicit UdpBase(io_udp_t* udp_) noexcept
      : Device(udp_ ? io_udp_get_dev(udp_) : nullptr),
        DatagramSocketBase(udp_ ? io_udp_get_sock_dgram(udp_) : nullptr),
        udp(udp_) {}

  operator io_udp_t*() const noexcept { return udp; }

  /// @see io_udp_open_ipv4()
  void
  open_ipv4(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_udp_open_ipv4(*this))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_udp_open_ipv4()
  void
  open_ipv4() {
    ::std::error_code ec;
    open_ipv4(ec);
    if (ec) throw ::std::system_error(ec, "open_ipv4");
  }

  /// @see io_udp_open_ipv6()
  void
  open_ipv6(bool v6only, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_udp_open_ipv6(*this, v6only))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_udp_open_ipv6()
  void
  open_ipv6(bool v6only = false) {
    ::std::error_code ec;
    open_ipv6(v6only, ec);
    if (ec) throw ::std::system_error(ec, "open_ipv6");
  }

 protected:
  io_udp_t* udp{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_UDP_HPP_
