/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the abstract serial port.
 *
 * @see lely/io2/serial.h
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

#ifndef LELY_IO2_SERIAL_HPP_
#define LELY_IO2_SERIAL_HPP_

#include <lely/io2/serial.h>
#include <lely/io2/stream.hpp>

namespace lely {
namespace io {

/// The serial port buffer to purge.
enum class SerialPurge : int {
  /// Purge data received but not read.
  RX = IO_SERIAL_PURGE_RX,
  /// Purge data written but not transmitted.
  TX = IO_SERIAL_PURGE_TX,
  /**
   * Purge both data received but not read and data written but not transmitted.
   */
  RXTX = IO_SERIAL_PURGE_RXTX
};

/// The flow control used by a serial port.
enum class SerialFlowControl : int {
  /// No flow control.
  NONE = IO_SERIAL_FLOW_CTRL_NONE,
  /// Software flow control.
  SW = IO_SERIAL_FLOW_CTRL_SW,
  /// Hardware flow control.
  HW = IO_SERIAL_FLOW_CTRL_HW
};

/// The serial port parity.
enum class SerialParity : int {
  /// No parity.
  NONE = IO_SERIAL_PARITY_NONE,
  /// Odd parity.
  ODD = IO_SERIAL_PARITY_ODD,
  /// Even parity.
  EVEN = IO_SERIAL_PARITY_EVEN,
};

/// The number of stop bits used by a serial port.
enum SerialStopBits : int {
  /// 1 stop bit.
  ONE = IO_SERIAL_STOP_BITS_ONE,
  /// 1.5 stop bits.
  ONE_FIVE = IO_SERIAL_STOP_BITS_ONE_FIVE,
  /// 2 stop bits.
  TWO = IO_SERIAL_STOP_BITS_TWO
};

/**
 * A reference to a serial port. This class is a wrapper around `#io_serial_t*`.
 */
class SerialBase : public StreamBase {
 public:
  using Device::operator io_dev_t*;
  using StreamBase::operator io_stream_t*;

  explicit SerialBase(io_serial_t* serial_) noexcept
      : Device(serial_ ? io_serial_get_dev(serial_) : nullptr),
        StreamBase(serial_ ? io_serial_get_stream(serial_) : nullptr),
        serial(serial_) {}

  operator io_serial_t*() const noexcept { return serial; }

  /// @see io_serial_send_break()
  void
  send_break(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_send_break(*this))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_send_break()
  void
  send_break() {
    ::std::error_code ec;
    send_break(ec);
    if (ec) throw ::std::system_error(ec, "send_break");
  }

  /// @see io_serial_flush()
  void
  flush(::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_flush(*this))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_flush()
  void
  flush() {
    ::std::error_code ec;
    flush(ec);
    if (ec) throw ::std::system_error(ec, "flush");
  }

  /// @see io_serial_purge()
  void
  purge(SerialPurge how, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_purge(*this, static_cast<int>(how)))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_purge()
  void
  purge(SerialPurge how) {
    ::std::error_code ec;
    purge(how, ec);
    if (ec) throw ::std::system_error(ec, "purge");
  }

  /// @see io_serial_get_baud_rate()
  int
  baud_rate() const noexcept {
    return io_serial_get_baud_rate(*this);
  }

  /// @see io_serial_set_baud_rate()
  void
  baud_rate(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_baud_rate(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_baud_rate()
  void
  baud_rate(int optval) {
    ::std::error_code ec;
    baud_rate(optval, ec);
    if (ec) throw ::std::system_error(ec, "baud_rate");
  }

  /// @see io_serial_get_flow_ctrl()
  SerialFlowControl
  flow_control() const noexcept {
    return static_cast<SerialFlowControl>(io_serial_get_flow_ctrl(*this));
  }

  /// @see io_serial_set_flow_ctrl()
  void
  flow_control(SerialFlowControl optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_flow_ctrl(*this, static_cast<int>(optval)))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_flow_ctrl()
  void
  flow_control(SerialFlowControl optval) {
    ::std::error_code ec;
    flow_control(optval, ec);
    if (ec) throw ::std::system_error(ec, "flow_control");
  }

  /// @see io_serial_get_stop_bits()
  SerialStopBits
  stop_bits() const noexcept {
    return static_cast<SerialStopBits>(io_serial_get_stop_bits(*this));
  }

  /// @see io_serial_set_stop_bits()
  void
  stop_bits(SerialStopBits optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_stop_bits(*this, static_cast<int>(optval)))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_stop_bits()
  void
  stop_bits(SerialStopBits optval) {
    ::std::error_code ec;
    stop_bits(optval, ec);
    if (ec) throw ::std::system_error(ec, "stop_bits");
  }

  /// @see io_serial_get_parity()
  SerialParity
  parity() const noexcept {
    return static_cast<SerialParity>(io_serial_get_parity(*this));
  }

  /// @see io_serial_set_parity()
  void
  parity(SerialParity optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_parity(*this, static_cast<int>(optval)))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_parity()
  void
  parity(SerialParity optval) {
    ::std::error_code ec;
    parity(optval, ec);
    if (ec) throw ::std::system_error(ec, "parity");
  }

  /// @see io_serial_get_char_size()
  int
  char_size() const noexcept {
    return io_serial_get_char_size(*this);
  }

  /// @see io_serial_set_char_size()
  void
  char_size(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_char_size(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_char_size()
  void
  char_size(int optval) {
    ::std::error_code ec;
    char_size(optval, ec);
    if (ec) throw ::std::system_error(ec, "char_size");
  }

  /// @see io_serial_get_rx_timeout()
  int
  rx_timeout() const noexcept {
    return io_serial_get_rx_timeout(*this);
  }

  /// @see io_serial_set_rx_timeout()
  void
  rx_timeout(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_rx_timeout(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_rx_timeout()
  void
  rx_timeout(int optval) {
    ::std::error_code ec;
    rx_timeout(optval, ec);
    if (ec) throw ::std::system_error(ec, "rx_timeout");
  }

  /// @see io_serial_get_tx_timeout()
  int
  tx_timeout() const noexcept {
    return io_serial_get_tx_timeout(*this);
  }

  /// @see io_serial_set_tx_timeout()
  void
  tx_timeout(int optval, ::std::error_code& ec) noexcept {
    int errsv = get_errc();
    set_errc(0);
    if (!io_serial_set_tx_timeout(*this, optval))
      ec.clear();
    else
      ec = util::make_error_code();
    set_errc(errsv);
  }

  /// @see io_serial_set_tx_timeout()
  void
  tx_timeout(int optval) {
    ::std::error_code ec;
    tx_timeout(optval, ec);
    if (ec) throw ::std::system_error(ec, "tx_timeout");
  }

 protected:
  io_serial_t* serial{nullptr};
};

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_SERIAL_HPP_
