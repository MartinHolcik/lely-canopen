/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the Bluetooth RFCOMM declarations.
 *
 * @see lely/io2/rfcomm.h
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

#ifndef LELY_IO2_RFCOMM_HPP_
#define LELY_IO2_RFCOMM_HPP_

#include <lely/io2/bth.hpp>
#include <lely/io2/endp.hpp>
#include <lely/io2/rfcomm.h>

#include <string>

namespace lely {
namespace io {

template <>
inline const io_endp_bth_rfcomm*
endpoint_cast<io_endp_bth_rfcomm>(const io_endp* endp) {
  if (endp->addr->family != IO_ADDR_BTH || endp->protocol != IO_BTHPROTO_RFCOMM)
    throw bad_endpoint_cast();
  return reinterpret_cast<const io_endp_bth_rfcomm*>(endp);
}

template <>
inline io_endp_bth_rfcomm*
endpoint_cast<io_endp_bth_rfcomm>(io_endp* endp) {
  if (endp->addr->family != IO_ADDR_BTH || endp->protocol != IO_BTHPROTO_RFCOMM)
    throw bad_endpoint_cast();
  return reinterpret_cast<io_endp_bth_rfcomm*>(endp);
}

/// A Bluetooth RFCOMM endpoint.
class BluetoothRfcommEndpoint : public io_endp_bth_rfcomm {
 public:
  using channel_type = uint_least8_t;

  BluetoothRfcommEndpoint() noexcept
      : io_endp_bth_rfcomm IO_ENDP_BTH_RFCOMM_INIT(this) {}

  BluetoothRfcommEndpoint(const io_endp_bth_rfcomm& endp) noexcept
      : io_endp_bth_rfcomm(endp) {
    addr = address();
  }

  BluetoothRfcommEndpoint&
  operator=(const io_endp_bth_rfcomm& endp) noexcept {
    io_endp_bth_rfcomm::operator=(endp);
    addr = address();
    return *this;
  }

  BluetoothRfcommEndpoint(const BluetoothRfcommEndpoint& endp) noexcept
      : BluetoothRfcommEndpoint(static_cast<const io_endp_bth_rfcomm&>(endp)) {}

  BluetoothRfcommEndpoint&
  operator=(const BluetoothRfcommEndpoint& endp) noexcept {
    return *this = static_cast<const io_endp_bth_rfcomm&>(endp);
  }

  BluetoothRfcommEndpoint(const io_endp& endp)
      : BluetoothRfcommEndpoint(
            endpoint_cast<const io_endp_bth_rfcomm&>(endp)) {}

  BluetoothRfcommEndpoint&
  operator=(const io_endp& endp) {
    return *this = endpoint_cast<const io_endp_bth_rfcomm&>(endp);
  }

  BluetoothRfcommEndpoint(const io_addr_bth& addr,
                          channel_type channel_ = 0) noexcept
      : BluetoothRfcommEndpoint() {
    address() = addr;
    channel = channel_;
  }

  BluetoothRfcommEndpoint(const char* str, channel_type channel = 0)
      : BluetoothRfcommEndpoint(BluetoothAddress(str), channel) {}

  BluetoothRfcommEndpoint(const ::std::string& str, channel_type channel = 0)
      : BluetoothRfcommEndpoint(BluetoothAddress(str), channel) {}

  operator io_endp*() noexcept { return reinterpret_cast<io_endp*>(this); }

  operator const io_endp*() const noexcept {
    return reinterpret_cast<const io_endp*>(this);
  }

  BluetoothAddress&
  address() noexcept {
    return *static_cast<BluetoothAddress*>(&bth);
  }

  const BluetoothAddress&
  address() const noexcept {
    return *static_cast<const BluetoothAddress*>(&bth);
  }
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_RFCOMM_HPP_
