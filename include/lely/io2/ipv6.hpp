/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the IPv6 address declarations.
 *
 * @see lely/io2/ipv6.h
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

#ifndef LELY_IO2_IPV6_HPP_
#define LELY_IO2_IPV6_HPP_

#include <lely/io2/addr.hpp>
#include <lely/io2/ipv6.h>
#include <lely/util/error.hpp>

#include <array>
#include <string>

namespace lely {
namespace io {

template <>
inline const io_addr_ipv6*
address_cast<io_addr_ipv6>(const io_addr* addr) {
  if (addr->family != IO_ADDR_IPV6) throw bad_address_cast();
  return reinterpret_cast<const io_addr_ipv6*>(addr);
}

template <>
inline io_addr_ipv6*
address_cast<io_addr_ipv6>(io_addr* addr) {
  if (addr->family != IO_ADDR_IPV6) throw bad_address_cast();
  return reinterpret_cast<io_addr_ipv6*>(addr);
}

/// An IPv6 Address.
class Ipv6Address : public io_addr_ipv6 {
 public:
  using bytes_type = ::std::array<unsigned char, 16>;
  using scope_id_type = uint_least32_t;

  /// @see io_addr_ipv6_set_any()
  Ipv6Address() noexcept : io_addr_ipv6 IO_ADDR_IPV6_INIT {}

  Ipv6Address(const io_addr_ipv6& addr) noexcept : io_addr_ipv6(addr) {}

  Ipv6Address(const io_addr& addr)
      : io_addr_ipv6(address_cast<const io_addr_ipv6&>(addr)) {}

  Ipv6Address&
  operator=(const io_addr& addr) {
    return *this = address_cast<const io_addr_ipv6&>(addr);
  }

  /// @see io_addr_ipv6_set_from_bytes()
  Ipv6Address(const bytes_type& bytes) noexcept { *this = bytes; }

  /// @see io_addr_ipv6_set_from_bytes()
  Ipv6Address&
  operator=(const bytes_type& bytes) noexcept {
    io_addr_ipv6_set_from_bytes(this, bytes.data());
    return *this;
  }

  /// @see make_ipv6_address()
  Ipv6Address(const char* str) { *this = str; }

  /// @see make_ipv6_address()
  Ipv6Address& operator=(const char* str);

  /// @see make_ipv6_address()
  Ipv6Address(const ::std::string& str) { *this = str; }

  /// @see make_ipv6_address()
  Ipv6Address& operator=(const ::std::string& str);

  operator io_addr*() noexcept {
    return reinterpret_cast<io_addr*>(this);
  }

  operator const io_addr*() const noexcept {
    return reinterpret_cast<const io_addr*>(this);
  }

#define LELY_IO_DEFINE_IPV6(name) \
  /** @see io_addr_is_ipv6_##name() */ \
  bool is_##name() const noexcept { return io_addr_is_ipv6_##name(*this) != 0; }

  LELY_IO_DEFINE_IPV6(unspecified)
  LELY_IO_DEFINE_IPV6(loopback)
  LELY_IO_DEFINE_IPV6(multicast)
  LELY_IO_DEFINE_IPV6(linklocal)
  LELY_IO_DEFINE_IPV6(sitelocal)
  LELY_IO_DEFINE_IPV6(v4mapped)
  LELY_IO_DEFINE_IPV6(v4compat)
  LELY_IO_DEFINE_IPV6(mc_nodelocal)
  LELY_IO_DEFINE_IPV6(mc_linklocal)
  LELY_IO_DEFINE_IPV6(mc_sitelocal)
  LELY_IO_DEFINE_IPV6(mc_orglocal)
  LELY_IO_DEFINE_IPV6(mc_global)

#undef LELY_IO_DEFINE_IPV6

  /// @see io_addr_ipv6_to_bytes()
  bytes_type
  to_bytes() const noexcept {
    bytes_type bytes{0};
    io_addr_ipv6_to_bytes(this, bytes.data());
    return bytes;
  }

  /// @see io_addr_ipv6_to_string()
  ::std::string
  to_string() const {
    char str[IO_ADDR_IPV6_STRLEN] = {0};
    io_addr_ipv6_to_string(this, str);
    return ::std::string{str};
  }

  /// @see io_addr_ipv6_set_any()
  static Ipv6Address
  any() noexcept {
    return Ipv6Address();
  }

  /// @see io_addr_ipv6_set_loopback()
  static Ipv6Address
  loopback() noexcept {
    Ipv6Address addr;
    io_addr_ipv6_set_loopback(&addr);
    return addr;
  }
};

/// @see io_addr_ipv6_set_from_string()
inline Ipv6Address
make_ipv6_address(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv6Address addr;
  ec.clear();
  if (io_addr_ipv6_set_from_string(&addr, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return addr;
}

/// @see io_addr_ipv6_set_from_string()
inline Ipv6Address
make_ipv6_address(const char* str) {
  ::std::error_code ec;
  auto addr = make_ipv6_address(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv6_address");
  return addr;
}

/// @see io_addr_ipv6_set_from_string()
inline Ipv6Address
make_ipv6_address(const ::std::string& str, ::std::error_code& ec) noexcept {
  return make_ipv6_address(str.c_str(), ec);
}

/// @see io_addr_ipv6_set_from_string()
inline Ipv6Address
make_ipv6_address(const ::std::string& str) {
  return make_ipv6_address(str.c_str());
}

inline Ipv6Address&
Ipv6Address::operator=(const char* str) {
  return *this = make_ipv6_address(str);
}

inline Ipv6Address&
Ipv6Address::operator=(const ::std::string& str) {
  return *this = make_ipv6_address(str);
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_IPV6_HPP_
