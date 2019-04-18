/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the Bluetooth address declarations.
 *
 * @see lely/io2/bth.h
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

#ifndef LELY_IO2_BTH_HPP_
#define LELY_IO2_BTH_HPP_

#include <lely/io2/addr.hpp>
#include <lely/io2/bth.h>
#include <lely/util/error.hpp>

#include <array>
#include <string>

namespace lely {
namespace io {

template <>
inline const io_addr_bth*
address_cast<io_addr_bth>(const io_addr* addr) {
  if (addr->family != IO_ADDR_BTH) throw bad_address_cast();
  return reinterpret_cast<const io_addr_bth*>(addr);
}

template <>
inline io_addr_bth*
address_cast<io_addr_bth>(io_addr* addr) {
  if (addr->family != IO_ADDR_BTH) throw bad_address_cast();
  return reinterpret_cast<io_addr_bth*>(addr);
}

/// A Bluetooth Address.
class BluetoothAddress : public io_addr_bth {
 public:
  using uint_type = uint_least64_t;
  using bytes_type = ::std::array<unsigned char, 6>;

  /// @see io_addr_bth_set_any()
  BluetoothAddress() noexcept : io_addr_bth IO_ADDR_BTH_INIT {}

  BluetoothAddress(const io_addr_bth& addr) noexcept : io_addr_bth(addr) {}

  BluetoothAddress(const io_addr& addr)
      : io_addr_bth(address_cast<const io_addr_bth&>(addr)) {}

  BluetoothAddress&
  operator=(const io_addr& addr) {
    return *this = address_cast<const io_addr_bth&>(addr);
  }

  /// @see io_addr_bth_set_from_uint()
  BluetoothAddress(uint_type val) noexcept { *this = val; }

  /// @see io_addr_bth_set_from_uint()
  BluetoothAddress&
  operator=(uint_type val) noexcept {
    io_addr_bth_set_from_uint(this, val);
    return *this;
  }

  /// @see io_addr_bth_set_from_bytes()
  BluetoothAddress(const bytes_type& bytes) noexcept { *this = bytes; }

  /// @see io_addr_bth_set_from_bytes()
  BluetoothAddress&
  operator=(const bytes_type& bytes) noexcept {
    io_addr_bth_set_from_bytes(this, bytes.data());
    return *this;
  }

  /// @see make_bth_address()
  BluetoothAddress(const char* str) { *this = str; }

  /// @see make_bth_address()
  BluetoothAddress& operator=(const char* str);

  /// @see make_bth_address()
  BluetoothAddress(const ::std::string& str) { *this = str; }

  /// @see make_bth_address()
  BluetoothAddress& operator=(const ::std::string& str);

  operator io_addr*() noexcept {
    return reinterpret_cast<io_addr*>(this);
  }

  operator const io_addr*() const noexcept {
    return reinterpret_cast<const io_addr*>(this);
  }

  /// @see io_addr_is_bth_unspecified()
  bool
  is_unspecified() const noexcept {
    return io_addr_is_bth_unspecified(*this) != 0;
  }

  /// @see io_addr_bth_to_uint()
  uint_type
  to_uint() const noexcept {
    return io_addr_bth_to_uint(this);
  }

  /// @see io_addr_bth_to_bytes()
  bytes_type
  to_bytes() const noexcept {
    bytes_type bytes{0};
    io_addr_bth_to_bytes(this, bytes.data());
    return bytes;
  }

  /// @see io_addr_bth_to_string()
  ::std::string
  to_string() const {
    char str[IO_ADDR_BTH_STRLEN] = {0};
    io_addr_bth_to_string(this, str);
    return ::std::string{str};
  }

  /// @see io_addr_bth_set_any()
  static BluetoothAddress
  any() noexcept {
    return BluetoothAddress();
  }
};

/// @see io_addr_bth_set_from_string()
inline BluetoothAddress
make_bluetooth_address(const char* str, ::std::error_code& ec) noexcept {
  int errsv = get_errc();
  set_errc(0);
  BluetoothAddress addr;
  ec.clear();
  if (io_addr_bth_set_from_string(&addr, str) == -1)
    ec = util::make_error_code();
  set_errc(errsv);
  return addr;
}

/// @see io_addr_bth_set_from_string()
inline BluetoothAddress
make_bluetooth_address(const char* str) {
  ::std::error_code ec;
  auto addr = make_bluetooth_address(str, ec);
  if (ec) throw ::std::system_error(ec, "make_bluetooth_address");
  return addr;
}

/// @see io_addr_bth_set_from_string()
inline BluetoothAddress
make_bluetooth_address(const ::std::string& str,
                       ::std::error_code& ec) noexcept {
  return make_bluetooth_address(str.c_str(), ec);
}

/// @see io_addr_bth_set_from_string()
inline BluetoothAddress
make_bluetooth_address(const ::std::string& str) {
  return make_bluetooth_address(str.c_str());
}

inline BluetoothAddress&
BluetoothAddress::operator=(const char* str) {
  return *this = make_bluetooth_address(str);
}

inline BluetoothAddress&
BluetoothAddress::operator=(const ::std::string& str) {
  return *this = make_bluetooth_address(str);
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_BTH_HPP_
