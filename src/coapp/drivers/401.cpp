/**@file
 * This file is part of the C++ CANopen application library; it contains the
 * implementation of the logical device driver interface for generic I/O modules
 * (CiA 401-1 v3.1.0).
 *
 * @see lely/coapp/drivers/401.hpp
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

#include "../coapp.hpp"

#if !LELY_NO_COAPP_MASTER

#include <lely/coapp/drivers/401.hpp>

#include <array>
#include <string>

#include <cassert>

namespace lely {

namespace canopen {

namespace {

template <int>
struct DigitalChannel;

template <>
struct DigitalChannel<8> {
  using type = uint8_t;

  static void
  check(int channel, const char* what_arg) {
    if (channel < 1)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number < 1");
    if (channel > 8 * 254)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number > 2032");
    if ((channel - 1) % 8)
      throw ::std::invalid_argument(
          ::std::string(what_arg) +
          ": invalid digital I/O channel number for 8-bit access");
  }

  static uint16_t
  idx(uint16_t idx, int) noexcept {
    return idx;
  }

  static uint8_t
  subidx(int channel) noexcept {
    assert(channel >= 1 && channel <= 8 * 254);
    assert(!((channel - 1) % 8));

    return (channel - 1) / 8 + 1;
  }
};

template <>
struct DigitalChannel<1> {
  using type = bool;

  static void
  check(int channel, const char* what_arg) {
    if (channel < 1)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number < 1");
    if (channel > 8 * 128)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number > 1024");
  }

  static uint16_t
  idx(uint16_t idx, int channel) noexcept {
    assert(channel >= 1 && channel <= 8 * 128);

    return idx + (channel - 1) / 128;
  }

  static uint8_t
  subidx(int channel) noexcept {
    assert(channel >= 1 && channel <= 8 * 128);

    return (channel - 1) % 128 + 1;
  }
};

template <>
struct DigitalChannel<16> {
  using type = uint16_t;

  static void
  check(int channel, const char* what_arg) {
    if (channel < 1)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number < 1");
    if (channel > 16 * 254)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number > 4064");
    if ((channel - 1) % 16)
      throw ::std::invalid_argument(
          ::std::string(what_arg) +
          ": invalid digital I/O channel number for 16-bit access");
  }

  static uint16_t
  idx(uint16_t idx, int) noexcept {
    return idx;
  }

  static uint8_t
  subidx(int channel) noexcept {
    assert(channel >= 1 && channel <= 16 * 254);
    assert(!((channel - 1) % 16));

    return (channel - 1) / 16 + 1;
  }
};

template <>
struct DigitalChannel<32> {
  using type = uint32_t;

  static void
  check(int channel, const char* what_arg) {
    if (channel < 1)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number < 1");
    if (channel > 32 * 254)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": digital I/O channel number > 8128");
    if ((channel - 1) % 32)
      throw ::std::invalid_argument(
          ::std::string(what_arg) +
          ": invalid digital I/O channel number for 32-bit access");
  }

  static uint16_t
  idx(uint16_t idx, int) noexcept {
    return idx;
  }

  static uint8_t
  subidx(int channel) noexcept {
    assert(channel >= 1 && channel <= 32 * 254);
    assert(!((channel - 1) % 32));

    return (channel - 1) / 32 + 1;
  }
};

SdoFuture<bool>
AsyncReadDigital(Basic401Driver* self, uint16_t idx, int channel,
                 const char* what_arg) {
  int i = ((channel - 1) & ~7) + 1;
  DigitalChannel<8>::check(i, what_arg);
  idx = DigitalChannel<8>::idx(idx, i);
  auto subidx = DigitalChannel<8>::subidx(i);
  return self->AsyncRead<uint8_t>(idx, subidx)
      .then(self->GetExecutor(),
            [channel, what_arg](SdoFuture<uint8_t> f) -> bool {
              return (f.get().value() >> ((channel - 1) % 8)) & 1;
            });
}

SdoFuture<void>
AsyncWriteDigital(Basic401Driver* self, uint16_t idx, int channel, bool value,
                  const char* what_arg) {
  int i = ((channel - 1) & ~7) + 1;
  DigitalChannel<8>::check(i, what_arg);
  idx = DigitalChannel<8>::idx(idx, i);
  auto subidx = DigitalChannel<8>::subidx(i);
  return self->AsyncRead<uint8_t>(idx, subidx)
      .then(self->GetExecutor(),
            [self, idx, subidx, channel, value,
             what_arg](SdoFuture<uint8_t> f) -> SdoFuture<void> {
              auto result = f.get().value();
              uint8_t mask = 1u << ((channel - 1) % 8);
              if (value && !(result & mask)) {
                return self->AsyncWrite<uint8_t>(idx, subidx, result | mask);
              } else if (!value && (result & mask)) {
                return self->AsyncWrite<uint8_t>(idx, subidx, result & ~mask);
              } else {
                return make_empty_sdo_future();
              }
            });
}

struct AnalogChannel {
  static void
  check(int channel, const char* what_arg) {
    if (channel < 1)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": analog I/O channel number < 1");
    if (channel > 254)
      throw ::std::out_of_range(::std::string(what_arg) +
                                ": analog I/O channel number > 254");
  }
};

}  // namespace

struct Basic401Driver::Impl_ {
  void SetDigitalInput8(Basic401Driver* self, int i, uint8_t value) noexcept;
  void SetDigitalInput1(Basic401Driver* self, int i, bool value) noexcept;
  void SetDigitalInput16(Basic401Driver* self, int i, uint16_t value) noexcept;
  void SetDigitalInput32(Basic401Driver* self, int i, uint32_t value) noexcept;
  void OnDigitalInput(Basic401Driver* self, int i, uint32_t value,
                      uint32_t mask);

  ::std::array<uint32_t, 254> di32{{0}};
};

Basic401Driver::Basic401Driver(BasicDriver& driver, int num, uint16_t info)
    : BasicLogicalDriver(driver, num,
                         401 | (static_cast<uint32_t>(info) << 16)),
      impl_(new Impl_()) {}

Basic401Driver::~Basic401Driver() = default;

#define LELY_COAPP_DEFINE_GET_RPDO_DIGITAL(name, access, idx_) \
  DigitalChannel<access>::type Basic401Driver::GetDigital##name(int i) const { \
    DigitalChannel<access>::check(i, "GetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return rpdo_mapped[idx][subidx]; \
  } \
\
  DigitalChannel<access>::type Basic401Driver::GetDigital##name( \
      int i, ::std::error_code& ec) const { \
    DigitalChannel<access>::check(i, "GetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return rpdo_mapped[idx][subidx].Read<DigitalChannel<access>::type>(ec); \
  }

#define LELY_COAPP_DEFINE_GET_TPDO_DIGITAL(name, access, idx_) \
  DigitalChannel<access>::type Basic401Driver::GetDigital##name(int i) const { \
    DigitalChannel<access>::check(i, "GetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return tpdo_mapped[idx][subidx]; \
  } \
\
  DigitalChannel<access>::type Basic401Driver::GetDigital##name( \
      int i, ::std::error_code& ec) const { \
    DigitalChannel<access>::check(i, "GetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return tpdo_mapped[idx][subidx].Read<DigitalChannel<access>::type>(ec); \
  }

#define LELY_COAPP_DEFINE_SET_TPDO_DIGITAL(name, access, idx_) \
  void Basic401Driver::SetDigital##name(int i, \
                                        DigitalChannel<access>::type value) { \
    DigitalChannel<access>::check(i, "SetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    tpdo_mapped[idx][subidx] = value; \
  } \
\
  void Basic401Driver::SetDigital##name( \
      int i, DigitalChannel<access>::type value, ::std::error_code& ec) { \
    DigitalChannel<access>::check(i, "SetDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    tpdo_mapped[idx][subidx].Write(value, ec); \
  }

#define LELY_COAPP_DEFINE_TPDO_DIGITAL(name, access, idx) \
  LELY_COAPP_DEFINE_GET_TPDO_DIGITAL(name, access, idx) \
  LELY_COAPP_DEFINE_SET_TPDO_DIGITAL(name, access, idx)

#define LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(name, access, idx_) \
  SdoFuture<DigitalChannel<access>::type> \
      Basic401Driver::AsyncReadDigital##name(int i) { \
    DigitalChannel<access>::check(i, "AsyncReadDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return AsyncRead<DigitalChannel<access>::type>(idx, subidx); \
  }

#define LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL(name, access, idx_) \
  SdoFuture<void> Basic401Driver::AsyncWriteDigital##name( \
      int i, DigitalChannel<access>::type value) { \
    DigitalChannel<access>::check(i, "AsyncWriteDigital" #name); \
    auto idx = DigitalChannel<access>::idx(idx_, i); \
    auto subidx = DigitalChannel<access>::subidx(i); \
    return AsyncWrite(idx, subidx, value); \
  }

#define LELY_COAPP_DEFINE_ASYNC_DIGITAL(name, access, idx) \
  LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(name, access, idx) \
  LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL(name, access, idx)

bool
Basic401Driver::HasDigitalInputs() const noexcept {
  return (DeviceType() >> 16) & 1;
}

LELY_COAPP_DEFINE_GET_RPDO_DIGITAL(Input8, 8, 0x6000)

SdoFuture<uint8_t>
Basic401Driver::AsyncReadDigitalInput8(int i) {
  DigitalChannel<8>::check(i, "AsyncReadDigitalInput8");

  uint8_t subidx = (i - 1) / 8 + 1;
  return AsyncRead<uint8_t>(0x6000, subidx)
      .then(GetExecutor(), [this, subidx](SdoFuture<uint8_t> f) {
        int i = (subidx - 1) * 8 + 1;
        auto value = f.get().value();
        impl_->SetDigitalInput8(this, i, value);
        return value;
      });
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputPolarity8, 8, 0x6002)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputFilterEnable8, 8, 0x6003)

SdoFuture<bool>
Basic401Driver::AsyncReadDigitalInputInterruptEnable() {
  return AsyncRead<bool>(0x6005, 0);
}

SdoFuture<void>
Basic401Driver::AsyncWriteDigitalInputInterruptEnable(bool value) {
  return AsyncWrite(0x6005, 0, value);
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptAny8, 8, 0x6006)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptPositive8, 8, 0x6007)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptNegative8, 8, 0x6008)

LELY_COAPP_DEFINE_GET_RPDO_DIGITAL(Input1, 1, 0x6020)

SdoFuture<bool>
Basic401Driver::AsyncReadDigitalInput1(int i) {
  DigitalChannel<1>::check(i, "AsyncReadDigitalInput1");

  uint16_t idx = 0x6020 + (i - 1) / 128;
  uint8_t subidx = (i - 1) % 128 + 1;
  return AsyncRead<bool>(idx, subidx)
      .then(GetExecutor(), [this, idx, subidx](SdoFuture<bool> f) {
        int i = (idx - 0x6020) * 128 + subidx;
        auto value = f.get().value();
        impl_->SetDigitalInput1(this, i, value);
        return value;
      });
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputPolarity1, 1, 0x6030)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputFilterEnable1, 1, 0x6038)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptAny1, 1, 0x6050)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptPositive1, 1, 0x6060)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptNegative1, 1, 0x6070)

LELY_COAPP_DEFINE_GET_RPDO_DIGITAL(Input16, 16, 0x6100)

SdoFuture<uint16_t>
Basic401Driver::AsyncReadDigitalInput16(int i) {
  DigitalChannel<16>::check(i, "AsyncReadDigitalInput16");

  uint16_t subidx = (i - 1) / 16 + 1;
  return AsyncRead<uint16_t>(0x6100, subidx)
      .then(GetExecutor(), [this, subidx](SdoFuture<uint16_t> f) {
        int i = (subidx - 1) * 16 + 1;
        auto value = f.get().value();
        impl_->SetDigitalInput16(this, i, value);
        return value;
      });
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputPolarity16, 16, 0x6102)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputFilterEnable16, 16, 0x6103)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptAny16, 16, 0x6106)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptPositive16, 16, 0x6107)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptNegative16, 16, 0x6108)

LELY_COAPP_DEFINE_GET_RPDO_DIGITAL(Input32, 32, 0x6120)

SdoFuture<uint32_t>
Basic401Driver::AsyncReadDigitalInput32(int i) {
  DigitalChannel<32>::check(i, "AsyncReadDigitalInput32");

  uint16_t subidx = (i - 1) / 32 + 1;
  return AsyncRead<uint32_t>(0x6120, subidx)
      .then(GetExecutor(), [this, subidx](SdoFuture<uint32_t> f) {
        int i = (subidx - 1) * 32 + 1;
        auto value = f.get().value();
        impl_->SetDigitalInput32(this, i, value);
        return value;
      });
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputPolarity32, 32, 0x6122)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputFilterEnable32, 32, 0x6123)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptAny32, 32, 0x6126)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptPositive32, 32, 0x6127)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(InputInterruptNegative32, 32, 0x6128)

bool
Basic401Driver::HasDigitalOutputs() const noexcept {
  return (DeviceType() >> 17) & 1;
}

LELY_COAPP_DEFINE_TPDO_DIGITAL(Output8, 8, 0x6200)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(Output8, 8, 0x6200)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputPolarity8, 8, 0x6202)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorMode8, 8, 0x6206)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorValue8, 8, 0x6207)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputFilterMask8, 8, 0x6208)

LELY_COAPP_DEFINE_TPDO_DIGITAL(Output1, 1, 0x6220)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(Output1, 1, 0x6220)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputPolarity1, 1, 0x6240)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorMode1, 1, 0x6250)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorValue1, 1, 0x6260)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputFilterMask1, 1, 0x6270)

LELY_COAPP_DEFINE_TPDO_DIGITAL(Output16, 16, 0x6300)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(Output16, 16, 0x6300)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputPolarity16, 16, 0x6302)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorMode16, 16, 0x6306)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorValue16, 16, 0x6307)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputFilterMask16, 16, 0x6308)

LELY_COAPP_DEFINE_TPDO_DIGITAL(Output32, 32, 0x6320)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(Output32, 32, 0x6320)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputPolarity32, 32, 0x6322)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorMode32, 32, 0x6326)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorValue32, 32, 0x6327)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputFilterMask32, 32, 0x6328)

#undef LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL
#undef LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL
#undef LELY_COAPP_DEFINE_ASYNC_DIGITAL
#undef LELY_COAPP_DEFINE_TPDO_DIGITAL
#undef LELY_COAPP_DEFINE_SET_TPDO_DIGITAL
#undef LELY_COAPP_DEFINE_GET_TPDO_DIGITAL
#undef LELY_COAPP_DEFINE_GET_RPDO_DIGITAL

#define LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(name, idx) \
  SdoFuture<bool> Basic401Driver::AsyncReadDigital##name(int i) { \
    return AsyncReadDigital(this, idx, i, "AsyncReadDigital" #name); \
  }

#define LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL(name, idx) \
  SdoFuture<void> Basic401Driver::AsyncWriteDigital##name(int i, bool value) { \
    return AsyncWriteDigital(this, idx, i, value, "AsyncWriteDigital" #name); \
  }

#define LELY_COAPP_DEFINE_ASYNC_DIGITAL(name, idx) \
  LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(name, idx) \
  LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL(name, idx)

bool
Basic401Driver::GetDigitalInput(int i) const {
  if (i < 1)
    throw ::std::out_of_range(
        "GetDigitalInput: digital I/O channel number < 1");
  if (i > 32 * 254)
    throw ::std::out_of_range(
        "GetDigitalInput: digital I/O channel number > 8128");

  return (impl_->di32[(i - 1) / 32] >> ((i - 1) % 32)) & 1;
}

LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(Input, 0x6000)
LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(InputPolarity, 0x6002)
LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(InputFilterEnable, 0x6003)
LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(InputInterruptAny, 0x6006)
LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(InputInterruptPositive, 0x6007)
LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL(InputInterruptNegative, 0x6008)

bool
Basic401Driver::GetDigitalOutput(int i) const {
  return (GetDigitalOutput8(i) >> ((i - 1) % 8)) & 1;
}

bool
Basic401Driver::GetDigitalOutput(int i, ::std::error_code& ec) const {
  return (GetDigitalOutput8(i, ec) >> ((i - 1) % 8)) & 1;
}

void
Basic401Driver::SetDigitalOutput(int i, bool value) {
  auto result = GetDigitalOutput8(i);
  uint8_t mask = 1u << ((i - 1) % 8);
  if (value && !(result & mask)) {
    SetDigitalOutput8(i, result | mask);
  } else if (!value && (result & mask)) {
    SetDigitalOutput8(i, result & ~mask);
  }
}

void
Basic401Driver::SetDigitalOutput(int i, bool value, ::std::error_code& ec) {
  auto result = GetDigitalOutput8(i, ec);
  if (!ec) {
    uint8_t mask = 1u << ((i - 1) % 8);
    if (value && !(result & mask)) {
      SetDigitalOutput8(i, result | mask, ec);
    } else if (!value && (result & mask)) {
      SetDigitalOutput8(i, result & ~mask, ec);
    }
  }
}

LELY_COAPP_DEFINE_ASYNC_DIGITAL(Output, 0x6200)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputPolarity, 0x6202)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorMode, 0x6206)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputErrorValue, 0x6207)
LELY_COAPP_DEFINE_ASYNC_DIGITAL(OutputFilterMask, 0x6208)

#undef LELY_COAPP_DEFINE_ASYNC_READ_DIGITAL
#undef LELY_COAPP_DEFINE_ASYNC_WRITE_DIGITAL
#undef LELY_COAPP_DEFINE_ASYNC_DIGITAL

#define LELY_COAPP_DEFINE_GET_RPDO_ANALOG(name, type, idx) \
  type Basic401Driver::GetAnalog##name(int i) const { \
    AnalogChannel::check(i, "GetAnalog" #name); \
    return rpdo_mapped[idx][i]; \
  } \
\
  type Basic401Driver::GetAnalog##name(int i, ::std::error_code& ec) const { \
    AnalogChannel::check(i, "GetAnalog" #name); \
    return rpdo_mapped[idx][i].Read<type>(ec); \
  }

#define LELY_COAPP_DEFINE_GET_TPDO_ANALOG(name, type, idx) \
  type Basic401Driver::GetAnalog##name(int i) const { \
    AnalogChannel::check(i, "GetAnalog" #name); \
    return tpdo_mapped[idx][i]; \
  } \
\
  type Basic401Driver::GetAnalog##name(int i, ::std::error_code& ec) const { \
    AnalogChannel::check(i, "GetAnalog" #name); \
    return tpdo_mapped[idx][i].Read<type>(ec); \
  }

#define LELY_COAPP_DEFINE_SET_TPDO_ANALOG(name, type, idx) \
  void Basic401Driver::SetAnalog##name(int i, type value) { \
    AnalogChannel::check(i, "SetAnalog" #name); \
    tpdo_mapped[idx][i] = value; \
  } \
\
  void Basic401Driver::SetAnalog##name(int i, type value, \
                                       ::std::error_code& ec) { \
    AnalogChannel::check(i, "SetAnalog" #name); \
    tpdo_mapped[idx][i].Write(value, ec); \
  }

#define LELY_COAPP_DEFINE_TPDO_ANALOG(name, type, idx) \
  LELY_COAPP_DEFINE_GET_TPDO_ANALOG(name, type, idx) \
  LELY_COAPP_DEFINE_SET_TPDO_ANALOG(name, type, idx)

#define LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(name, type, idx) \
  SdoFuture<type> Basic401Driver::AsyncReadAnalog##name(int i) { \
    AnalogChannel::check(i, "AsyncReadAnalog" #name); \
    return AsyncRead<type>(idx, i); \
  }

#define LELY_COAPP_DEFINE_ASYNC_WRITE_ANALOG(name, type, idx) \
  SdoFuture<void> Basic401Driver::AsyncWriteAnalog##name(int i, type value) { \
    AnalogChannel::check(i, "AsyncWriteAnalog" #name); \
    return AsyncWrite(idx, i, value); \
  }

#define LELY_COAPP_DEFINE_ASYNC_ANALOG(name, type, idx) \
  LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(name, type, idx) \
  LELY_COAPP_DEFINE_ASYNC_WRITE_ANALOG(name, type, idx)

bool
Basic401Driver::HasAnalogInputs() const noexcept {
  return (DeviceType() >> 18) & 1;
}

LELY_COAPP_DEFINE_GET_RPDO_ANALOG(Input8, int8_t, 0x6400)
LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(Input8, int8_t, 0x6400)

LELY_COAPP_DEFINE_GET_RPDO_ANALOG(Input16, int16_t, 0x6401)
LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(Input16, int16_t, 0x6401)

LELY_COAPP_DEFINE_GET_RPDO_ANALOG(Input32, int32_t, 0x6402)
LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(Input32, int32_t, 0x6402)

LELY_COAPP_DEFINE_GET_RPDO_ANALOG(InputFloat, float, 0x6403)
LELY_COAPP_DEFINE_ASYNC_READ_ANALOG(InputFloat, float, 0x6403)

bool
Basic401Driver::HasAnalogOutputs() const noexcept {
  return (DeviceType() >> 19) & 1;
}

LELY_COAPP_DEFINE_TPDO_ANALOG(Output8, int8_t, 0x6410)
LELY_COAPP_DEFINE_ASYNC_ANALOG(Output8, int8_t, 0x6410)

LELY_COAPP_DEFINE_TPDO_ANALOG(Output16, int16_t, 0x6411)
LELY_COAPP_DEFINE_ASYNC_ANALOG(Output16, int16_t, 0x6411)

LELY_COAPP_DEFINE_TPDO_ANALOG(Output32, int32_t, 0x6412)
LELY_COAPP_DEFINE_ASYNC_ANALOG(Output32, int32_t, 0x6412)

LELY_COAPP_DEFINE_TPDO_ANALOG(OutputFloat, float, 0x6413)
LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputFloat, float, 0x6413)

SdoFuture<AnalogInputInterrupt>
Basic401Driver::AsyncReadAnalogInputInterruptTrigger(int i) {
  AnalogChannel::check(i, "AsyncReadAnalogInputInterruptTrigger");
  return AsyncRead<uint8_t>(0x6421, i).then(
      GetExecutor(), [](SdoFuture<uint8_t> f) {
        return static_cast<AnalogInputInterrupt>(f.get().value());
      });
}

SdoFuture<void>
Basic401Driver::AsyncWriteAnalogInputInterruptTrigger(
    int i, AnalogInputInterrupt value) {
  AnalogChannel::check(i, "AsyncWriteAnalogInputInterruptTrigger");
  return AsyncWrite(0x6421, i, static_cast<uint8_t>(value));
}

// TODO(jseldenthuis@lely.com): Add Async[...]AnalogInputInterruptSource()

SdoFuture<bool>
Basic401Driver::AsyncReadAnalogInputInterruptEnable() {
  return AsyncRead<bool>(0x6423, 0);
}

SdoFuture<void>
Basic401Driver::AsyncWriteAnalogInputInterruptEnable(bool value) {
  return AsyncWrite(0x6423, 0, value);
}

LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptUpper32, int32_t, 0x6424)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptLower32, int32_t, 0x6425)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptDelta32, uint32_t, 0x6426)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptNegative32, uint32_t, 0x6427)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptPositive32, uint32_t, 0x6428)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptUpperFloat, float, 0x6429)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptLowerFloat, float, 0x642A)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptDeltaFloat, float, 0x642B)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptNegativeFloat, float, 0x642C)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputInterruptPositiveFloat, float, 0x642D)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputOffsetFloat, float, 0x642E)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputScalingFloat, float, 0x642F)
// TODO(jseldenthuis@lely.com): Add Async[...]AnalogInputUnit()
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputOffset32, int32_t, 0x6431)
LELY_COAPP_DEFINE_ASYNC_ANALOG(InputScaling32, int32_t, 0x6431)

LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputOffsetFloat, float, 0x6441)
LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputScalingFloat, float, 0x6442)

SdoFuture<bool>
Basic401Driver::AsyncReadAnalogOutputErrorMode(int i) {
  AnalogChannel::check(i, "AsyncReadAnalogOutputErrorMode");
  return AsyncRead<uint8_t>(0x6443, i).then(
      GetExecutor(), [](SdoFuture<uint8_t> f) { return !!f.get().value(); });
}

SdoFuture<void>
Basic401Driver::AsyncWriteAnalogOutputErrorMode(int i, bool value) {
  AnalogChannel::check(i, "AsyncWriteAnalogOutputErrorMode");
  return AsyncWrite(0x6443, i, static_cast<uint8_t>(value));
}

LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputErrorValue32, int32_t, 0x6444)
LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputErrorValueFloat, float, 0x6445)
LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputOffset32, int32_t, 0x6446)
LELY_COAPP_DEFINE_ASYNC_ANALOG(OutputScaling32, int32_t, 0x6447)
// TODO(jseldenthuis@lely.com): Add Async[...]AnalogOutputUnit()

#undef LELY_COAPP_DEFINE_ASYNC_ANALOG
#undef LELY_COAPP_DEFINE_ASYNC_WRITE_ANALOG
#undef LELY_COAPP_DEFINE_ASYNC_READ_ANALOG
#undef LELY_COAPP_DEFINE_TPDO_ANALOG
#undef LELY_COAPP_DEFINE_SET_TPDO_ANALOG
#undef LELY_COAPP_DEFINE_GET_TPDO_ANALOG
#undef LELY_COAPP_DEFINE_GET_RPDO_ANALOG

void
Basic401Driver::OnRpdoWrite(uint16_t idx, uint8_t subidx) noexcept {
  switch (idx) {
    case 0x6000: {
      assert(subidx >= 1 && subidx <= 254);
      int i = (subidx - 1) * 8 + 1;
      uint8_t value = rpdo_mapped[idx][subidx];
      OnDigitalInput8(i, value);
      impl_->SetDigitalInput8(this, i, value);
      break;
    }
    case 0x6020:
    case 0x6021:
    case 0x6022:
    case 0x6023:
    case 0x6024:
    case 0x6025:
    case 0x6026:
    case 0x6027: {
      assert(subidx >= 1 && subidx <= 128);
      int i = (idx - 0x6020) * 128 + subidx;
      bool value = rpdo_mapped[idx][subidx];
      OnDigitalInput1(i, value);
      impl_->SetDigitalInput1(this, i, value);
      break;
    }
    case 0x6100: {
      assert(subidx >= 1 && subidx <= 254);
      int i = (subidx - 1) * 16 + 1;
      uint16_t value = rpdo_mapped[idx][subidx];
      OnDigitalInput16(i, value);
      impl_->SetDigitalInput16(this, i, value);
      break;
    }
    case 0x6120: {
      assert(subidx >= 1 && subidx <= 254);
      int i = (subidx - 1) * 32 + 1;
      uint32_t value = rpdo_mapped[idx][subidx];
      OnDigitalInput32(i, value);
      impl_->SetDigitalInput32(this, i, value);
      break;
    }
    case 0x6400:
      OnAnalogInput8(subidx, rpdo_mapped[idx][subidx]);
      break;
    case 0x6401:
      OnAnalogInput16(subidx, rpdo_mapped[idx][subidx]);
      break;
    case 0x6402:
      OnAnalogInput32(subidx, rpdo_mapped[idx][subidx]);
      break;
    case 0x6403:
      OnAnalogInputFloat(subidx, rpdo_mapped[idx][subidx]);
      break;
  }
}

void
Basic401Driver::Impl_::SetDigitalInput8(Basic401Driver* self, int i,
                                        uint8_t value) noexcept {
  assert(i >= 1 && i <= 8 * 254);

  uint8_t mask = (di32[(i - 1) / 32] >> ((i - 1) % 32)) ^ value;

  di32[(i - 1) / 32] &= ~(UINT32_C(0xff) << ((i - 1) % 32));
  di32[(i - 1) / 32] |= static_cast<uint32_t>(value) << ((i - 1) % 32);

  OnDigitalInput(self, i, value, mask);
}

void
Basic401Driver::Impl_::SetDigitalInput1(Basic401Driver* self, int i,
                                        bool value) noexcept {
  assert(i >= 1 && i <= 8 * 128);

  bool mask = ((di32[(i - 1) / 32] >> ((i - 1) % 32)) & 1) ^ value;

  if (value)
    di32[(i - 1) / 32] |= UINT32_C(1) << ((i - 1) % 32);
  else
    di32[(i - 1) / 32] &= ~(UINT32_C(1) << ((i - 1) % 32));

  OnDigitalInput(self, i, value, mask);
}

void
Basic401Driver::Impl_::SetDigitalInput16(Basic401Driver* self, int i,
                                         uint16_t value) noexcept {
  assert(i >= 1 && i <= 16 * 254);

  auto mask = uint16_t(di32[i / 32] >> ((i - 1) % 32)) ^ value;

  di32[(i - 1) / 32] &= ~(UINT32_C(0xffff) << ((i - 1) % 32));
  di32[(i - 1) / 32] |= static_cast<uint32_t>(value) << ((i - 1) % 32);

  OnDigitalInput(self, i, value, mask);
}

void
Basic401Driver::Impl_::SetDigitalInput32(Basic401Driver* self, int i,
                                         uint32_t value) noexcept {
  assert(i >= 1 && i <= 32 * 254);

  uint16_t mask = di32[(i - 1) / 32] ^ value;

  di32[(i - 1) / 32] = value;

  OnDigitalInput(self, i, value, mask);
}

void
Basic401Driver::Impl_::OnDigitalInput(Basic401Driver* self, int i,
                                      uint32_t value, uint32_t mask) {
  for (; mask; i++, value >>= 1, mask >>= 1) {
    if (mask & 1)
      self->GetExecutor().post(
          [self, i, value]() { self->OnDigitalInput(i, value & 1); });
  }
}

}  // namespace canopen

}  // namespace lely

#endif  // !LELY_NO_COAPP_MASTER
