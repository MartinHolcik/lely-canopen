/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the TCP declarations.
 *
 * @see lely/io2/tcp.h
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

#ifndef LELY_IO2_TCP_HPP_
#define LELY_IO2_TCP_HPP_

#include <lely/io2/endp.hpp>
#include <lely/io2/ipv4.hpp>
#include <lely/io2/ipv6.hpp>
#include <lely/io2/tcp.h>

#include <string>

namespace lely {
namespace io {

template <>
inline const io_endp_ipv4_tcp*
endpoint_cast<io_endp_ipv4_tcp>(const io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV4 || endp->protocol != IO_IPPROTO_TCP)
    throw bad_endpoint_cast();
  return reinterpret_cast<const io_endp_ipv4_tcp*>(endp);
}

template <>
inline io_endp_ipv4_tcp*
endpoint_cast<io_endp_ipv4_tcp>(io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV4 || endp->protocol != IO_IPPROTO_TCP)
    throw bad_endpoint_cast();
  return reinterpret_cast<io_endp_ipv4_tcp*>(endp);
}

/// An IPv4 TCP endpoint.
class Ipv4TcpEndpoint : public io_endp_ipv4_tcp {
 public:
  using port_type = uint_least16_t;

  Ipv4TcpEndpoint() noexcept : io_endp_ipv4_tcp IO_ENDP_IPV4_TCP_INIT(this) {}

  Ipv4TcpEndpoint(const io_endp_ipv4_tcp& endp) noexcept
      : io_endp_ipv4_tcp(endp) {
    addr = address();
  }

  Ipv4TcpEndpoint&
  operator=(const io_endp_ipv4_tcp& endp) noexcept {
    io_endp_ipv4_tcp::operator=(endp);
    addr = address();
    return *this;
  }

  Ipv4TcpEndpoint(const Ipv4TcpEndpoint& endp) noexcept
      : Ipv4TcpEndpoint(static_cast<const io_endp_ipv4_tcp&>(endp)) {}

  Ipv4TcpEndpoint&
  operator=(const Ipv4TcpEndpoint& endp) noexcept {
    return *this = static_cast<const io_endp_ipv4_tcp&>(endp);
  }

  Ipv4TcpEndpoint(const io_endp& endp)
      : Ipv4TcpEndpoint(endpoint_cast<const io_endp_ipv4_tcp&>(endp)) {}

  Ipv4TcpEndpoint&
  operator=(const io_endp& endp) {
    return *this = endpoint_cast<const io_endp_ipv4_tcp&>(endp);
  }

  Ipv4TcpEndpoint(const io_addr_ipv4& addr, port_type port_ = 0) noexcept
      : Ipv4TcpEndpoint() {
    address() = addr;
    port = port_;
  }

  Ipv4TcpEndpoint(const char* str, port_type port)
      : Ipv4TcpEndpoint(Ipv4Address(str), port) {}

  Ipv4TcpEndpoint(const ::std::string& str, port_type port)
      : Ipv4TcpEndpoint(Ipv4Address(str), port) {}

  /// @see make_ipv4_tcp_endpoint()
  Ipv4TcpEndpoint(const char* str) { *this = str; }

  /// @see make_ipv4_tcp_endpoint()
  Ipv4TcpEndpoint& operator=(const char* str);

  /// @see make_ipv4_tcp_endpoint()
  Ipv4TcpEndpoint(const ::std::string& str) { *this = str; }

  /// @see make_ipv4_tcp_endpoint()
  Ipv4TcpEndpoint& operator=(const ::std::string& str);

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

  /// @see io_endp_ipv4_tcp_to_string()
  ::std::string
  to_string() const {
    char str[IO_ENDP_IPV4_TCP_STRLEN] = {0};
    io_endp_ipv4_tcp_to_string(this, str);
    return ::std::string{str};
  }
};

/// @see io_endp_ipv4_tcp_set_from_string()
inline Ipv4TcpEndpoint
make_ipv4_tcp_endpoint(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv4TcpEndpoint endp;
  ec.clear();
  if (io_endp_ipv4_tcp_set_from_string(&endp, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return endp;
}

/// @see io_endp_ipv4_tcp_set_from_string()
inline Ipv4TcpEndpoint
make_ipv4_tcp_endpoint(const char* str) {
  ::std::error_code ec;
  auto endp = make_ipv4_tcp_endpoint(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv4_tcp_endpoint");
  return endp;
}

/// @see io_endp_ipv4_tcp_set_from_string()
inline Ipv4TcpEndpoint
make_ipv4_tcp_endpoint(const ::std::string& str,
                       ::std::error_code& ec) noexcept {
  return make_ipv4_tcp_endpoint(str.c_str(), ec);
}

/// @see io_endp_ipv4_tcp_set_from_string()
inline Ipv4TcpEndpoint
make_ipv4_tcp_endpoint(const ::std::string& str) {
  return make_ipv4_tcp_endpoint(str.c_str());
}

inline Ipv4TcpEndpoint&
Ipv4TcpEndpoint::operator=(const char* str) {
  return *this = make_ipv4_tcp_endpoint(str);
}

inline Ipv4TcpEndpoint&
Ipv4TcpEndpoint::operator=(const ::std::string& str) {
  return *this = make_ipv4_tcp_endpoint(str);
}

template <>
inline const io_endp_ipv6_tcp*
endpoint_cast<io_endp_ipv6_tcp>(const io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV6 || endp->protocol != IO_IPPROTO_TCP)
    throw bad_endpoint_cast();
  return reinterpret_cast<const io_endp_ipv6_tcp*>(endp);
}

template <>
inline io_endp_ipv6_tcp*
endpoint_cast<io_endp_ipv6_tcp>(io_endp* endp) {
  if (endp->addr->family != IO_ADDR_IPV6 || endp->protocol != IO_IPPROTO_TCP)
    throw bad_endpoint_cast();
  return reinterpret_cast<io_endp_ipv6_tcp*>(endp);
}

/// An IPv6 TCP endpoint.
class Ipv6TcpEndpoint : public io_endp_ipv6_tcp {
 public:
  using port_type = uint_least16_t;

  Ipv6TcpEndpoint() noexcept : io_endp_ipv6_tcp IO_ENDP_IPV6_TCP_INIT(this) {}

  Ipv6TcpEndpoint(const io_endp_ipv6_tcp& endp) noexcept
      : io_endp_ipv6_tcp(endp) {
    addr = address();
  }

  Ipv6TcpEndpoint&
  operator=(const io_endp_ipv6_tcp& endp) noexcept {
    io_endp_ipv6_tcp::operator=(endp);
    addr = address();
    return *this;
  }

  Ipv6TcpEndpoint(const Ipv6TcpEndpoint& endp) noexcept
      : Ipv6TcpEndpoint(static_cast<const io_endp_ipv6_tcp&>(endp)) {}

  Ipv6TcpEndpoint&
  operator=(const Ipv6TcpEndpoint& endp) noexcept {
    return *this = static_cast<const io_endp_ipv6_tcp&>(endp);
  }

  Ipv6TcpEndpoint(const io_endp& endp)
      : Ipv6TcpEndpoint(endpoint_cast<const io_endp_ipv6_tcp&>(endp)) {}

  Ipv6TcpEndpoint&
  operator=(const io_endp& endp) {
    return *this = endpoint_cast<const io_endp_ipv6_tcp&>(endp);
  }

  Ipv6TcpEndpoint(const io_addr_ipv6& addr, port_type port_ = 0) noexcept
      : Ipv6TcpEndpoint() {
    address() = addr;
    port = port_;
  }

  Ipv6TcpEndpoint(const char* str, port_type port)
      : Ipv6TcpEndpoint(Ipv6Address(str), port) {}

  Ipv6TcpEndpoint(const ::std::string& str, port_type port)
      : Ipv6TcpEndpoint(Ipv6Address(str), port) {}

  /// @see make_ipv6_tcp_endpoint()
  Ipv6TcpEndpoint(const char* str) { *this = str; }

  /// @see make_ipv6_tcp_endpoint()
  Ipv6TcpEndpoint& operator=(const char* str);

  /// @see make_ipv6_tcp_endpoint()
  Ipv6TcpEndpoint(const ::std::string& str) { *this = str; }

  /// @see make_ipv6_tcp_endpoint()
  Ipv6TcpEndpoint& operator=(const ::std::string& str);

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

  /// @see io_endp_ipv6_tcp_to_string()
  ::std::string
  to_string() const {
    char str[IO_ENDP_IPV6_TCP_STRLEN] = {0};
    io_endp_ipv6_tcp_to_string(this, str);
    return ::std::string{str};
  }
};

/// @see io_endp_ipv6_tcp_set_from_string()
inline Ipv6TcpEndpoint
make_ipv6_tcp_endpoint(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv6TcpEndpoint endp;
  ec.clear();
  if (io_endp_ipv6_tcp_set_from_string(&endp, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return endp;
}

/// @see io_endp_ipv6_tcp_set_from_string()
inline Ipv6TcpEndpoint
make_ipv6_tcp_endpoint(const char* str) {
  ::std::error_code ec;
  auto endp = make_ipv6_tcp_endpoint(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv6_tcp_endpoint");
  return endp;
}

/// @see io_endp_ipv6_tcp_set_from_string()
inline Ipv6TcpEndpoint
make_ipv6_tcp_endpoint(const ::std::string& str,
                       ::std::error_code& ec) noexcept {
  return make_ipv6_tcp_endpoint(str.c_str(), ec);
}

/// @see io_endp_ipv6_tcp_set_from_string()
inline Ipv6TcpEndpoint
make_ipv6_tcp_endpoint(const ::std::string& str) {
  return make_ipv6_tcp_endpoint(str.c_str());
}

inline Ipv6TcpEndpoint&
Ipv6TcpEndpoint::operator=(const char* str) {
  return *this = make_ipv6_tcp_endpoint(str);
}

inline Ipv6TcpEndpoint&
Ipv6TcpEndpoint::operator=(const ::std::string& str) {
  return *this = make_ipv6_tcp_endpoint(str);
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_TCP_HPP_
