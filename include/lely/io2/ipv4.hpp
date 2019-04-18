/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the IPv4 address declarations.
 *
 * @see lely/io2/ipv4.h
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

#ifndef LELY_IO2_IPV4_HPP_
#define LELY_IO2_IPV4_HPP_

#include <lely/io2/addr.hpp>
#include <lely/io2/ipv4.h>
#include <lely/util/error.hpp>

#include <array>
#include <string>

namespace lely {
namespace io {

template <>
inline const io_addr_ipv4*
address_cast<io_addr_ipv4>(const io_addr* addr) {
  if (addr->family != IO_ADDR_IPV4) throw bad_address_cast();
  return reinterpret_cast<const io_addr_ipv4*>(addr);
}

template <>
inline io_addr_ipv4*
address_cast<io_addr_ipv4>(io_addr* addr) {
  if (addr->family != IO_ADDR_IPV4) throw bad_address_cast();
  return reinterpret_cast<io_addr_ipv4*>(addr);
}

/// An IPv4 Address.
class Ipv4Address : public io_addr_ipv4 {
 public:
  using uint_type = uint_least32_t;
  using bytes_type = ::std::array<unsigned char, 4>;

  /// @see io_addr_ipv4_set_any()
  Ipv4Address() noexcept : io_addr_ipv4 IO_ADDR_IPV4_INIT {}

  Ipv4Address(const io_addr_ipv4& addr) noexcept : io_addr_ipv4(addr) {}

  Ipv4Address(const io_addr& addr)
      : io_addr_ipv4(address_cast<const io_addr_ipv4&>(addr)) {}

  Ipv4Address&
  operator=(const io_addr& addr) {
    return *this = address_cast<const io_addr_ipv4&>(addr);
  }

  /// @see io_addr_ipv4_set_from_uint()
  Ipv4Address(uint_type val) noexcept { *this = val; }

  /// @see io_addr_ipv4_set_from_uint()
  Ipv4Address&
  operator=(uint_type val) noexcept {
    io_addr_ipv4_set_from_uint(this, val);
    return *this;
  }

  /// @see io_addr_ipv4_set_from_bytes()
  Ipv4Address(const bytes_type& bytes) noexcept { *this = bytes; }

  /// @see io_addr_ipv4_set_from_bytes()
  Ipv4Address&
  operator=(const bytes_type& bytes) noexcept {
    io_addr_ipv4_set_from_bytes(this, bytes.data());
    return *this;
  }

  /// @see make_ipv4_address()
  Ipv4Address(const char* str) { *this = str; }

  /// @see make_ipv4_address()
  Ipv4Address& operator=(const char* str);

  /// @see make_ipv4_address()
  Ipv4Address(const ::std::string& str) { *this = str; }

  /// @see make_ipv4_address()
  Ipv4Address& operator=(const ::std::string& str);

  operator io_addr*() noexcept {
    return reinterpret_cast<io_addr*>(this);
  }

  operator const io_addr*() const noexcept {
    return reinterpret_cast<const io_addr*>(this);
  }

#define LELY_IO_DEFINE_IPV4(name) \
  /** @see io_addr_is_ipv4_##name() */ \
  bool is_##name() const noexcept { return io_addr_is_ipv4_##name(*this) != 0; }

  LELY_IO_DEFINE_IPV4(unspecified)
  LELY_IO_DEFINE_IPV4(loopback)
  LELY_IO_DEFINE_IPV4(broadcast)
  LELY_IO_DEFINE_IPV4(multicast)

#undef LELY_IO_DEFINE_IPV4

  /// @see io_addr_ipv4_to_uint()
  uint_type
  to_uint() const noexcept {
    return io_addr_ipv4_to_uint(this);
  }

  /// @see io_addr_ipv4_to_bytes()
  bytes_type
  to_bytes() const noexcept {
    bytes_type bytes{0};
    io_addr_ipv4_to_bytes(this, bytes.data());
    return bytes;
  }

  /// @see io_addr_ipv4_to_string()
  ::std::string
  to_string() const {
    char str[IO_ADDR_IPV4_STRLEN] = {0};
    io_addr_ipv4_to_string(this, str);
    return ::std::string{str};
  }

  /// @see io_addr_ipv4_set_any()
  static Ipv4Address
  any() noexcept {
    return Ipv4Address();
  }

  /// @see io_addr_ipv4_set_loopback()
  static Ipv4Address
  loopback() noexcept {
    Ipv4Address addr;
    io_addr_ipv4_set_loopback(&addr);
    return addr;
  }

  /// @see io_addr_ipv4_set_broadcast()
  static Ipv4Address
  broadcast() noexcept {
    Ipv4Address addr;
    io_addr_ipv4_set_broadcast(&addr);
    return addr;
  }
};

/// @see io_addr_ipv4_set_from_string()
inline Ipv4Address
make_ipv4_address(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  Ipv4Address addr;
  ec.clear();
  if (io_addr_ipv4_set_from_string(&addr, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return addr;
}

/// @see io_addr_ipv4_set_from_string()
inline Ipv4Address
make_ipv4_address(const char* str) {
  ::std::error_code ec;
  auto addr = make_ipv4_address(str, ec);
  if (ec) throw ::std::system_error(ec, "make_ipv4_address");
  return addr;
}

/// @see io_addr_ipv4_set_from_string()
inline Ipv4Address
make_ipv4_address(const ::std::string& str, ::std::error_code& ec) noexcept {
  return make_ipv4_address(str.c_str(), ec);
}

/// @see io_addr_ipv4_set_from_string()
inline Ipv4Address
make_ipv4_address(const ::std::string& str) {
  return make_ipv4_address(str.c_str());
}

inline Ipv4Address&
Ipv4Address::operator=(const char* str) {
  return *this = make_ipv4_address(str);
}

inline Ipv4Address&
Ipv4Address::operator=(const ::std::string& str) {
  return *this = make_ipv4_address(str);
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_IPV4_HPP_
