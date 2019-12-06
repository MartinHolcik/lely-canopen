/**@file
 * This header file is part of the C++ CANopen application library; it contains
 * the logical device driver interface for generic I/O modules (CiA 401-1
 * v3.1.0).
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

#ifndef LELY_COAPP_DRIVERS_401_HPP_
#define LELY_COAPP_DRIVERS_401_HPP_

#include <lely/coapp/driver.hpp>

#include <memory>

namespace lely {

namespace canopen {

enum class AnalogInputInterrupt : uint8_t {
  UPPER = 1u << 0,
  LOWER = 1u << 1,
  DELTA = 1u << 2,
  NEGATIVE = 1u << 3,
  POSITIVE = 1u << 4,
  NONE = 0
};

/**
 * The base class of logical device drivers for generic I/O modules (CiA 401-1
 * v3.1.0).
 */
class Basic401Driver : public BasicLogicalDriver {
 public:
  Basic401Driver(BasicDriver& driver, int num = 1, uint16_t info = 0x000fu);

  ~Basic401Driver();

  /**
   * Returns true if the additional information in the device type indicates the
   * remote node implements digital inputs, and false if not.
   */
  bool HasDigitalInputs() const noexcept;

  uint8_t GetDigitalInput8(int i) const;
  uint8_t GetDigitalInput8(int i, ::std::error_code& ec) const;
  SdoFuture<uint8_t> AsyncReadDigitalInput8(int i);

  SdoFuture<uint8_t> AsyncReadDigitalInputPolarity8(int i);
  SdoFuture<void> AsyncWriteDigitalInputPolarity8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalInputFilterEnable8(int i);
  SdoFuture<void> AsyncWriteDigitalInputFilterEnable8(int i, uint8_t value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptEnable();
  SdoFuture<void> AsyncWriteDigitalInputInterruptEnable(bool value);

  SdoFuture<uint8_t> AsyncReadDigitalInputInterruptAny8(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptAny8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalInputInterruptPositive8(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptPositive8(int i,
                                                           uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalInputInterruptNegative8(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptNegative8(int i,
                                                           uint8_t value);

  bool GetDigitalInput1(int i) const;
  bool GetDigitalInput1(int i, ::std::error_code& ec) const;
  SdoFuture<bool> AsyncReadDigitalInput1(int i);

  SdoFuture<bool> AsyncReadDigitalInputPolarity1(int i);
  SdoFuture<void> AsyncWriteDigitalInputPolarity1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputFilterEnable1(int i);
  SdoFuture<void> AsyncWriteDigitalInputFilterEnable1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptAny1(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptAny1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptPositive1(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptPositive1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptNegative1(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptNegative1(int i, bool value);

  uint16_t GetDigitalInput16(int i) const;
  uint16_t GetDigitalInput16(int i, ::std::error_code& ec) const;
  SdoFuture<uint16_t> AsyncReadDigitalInput16(int i);

  SdoFuture<uint16_t> AsyncReadDigitalInputPolarity16(int i);
  SdoFuture<void> AsyncWriteDigitalInputPolarity16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalInputFilterEnable16(int i);
  SdoFuture<void> AsyncWriteDigitalInputFilterEnable16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalInputInterruptAny16(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptAny16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalInputInterruptPositive16(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptPositive16(int i,
                                                            uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalInputInterruptNegative16(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptNegative16(int i,
                                                            uint16_t value);

  uint32_t GetDigitalInput32(int i) const;
  uint32_t GetDigitalInput32(int i, ::std::error_code& ec) const;
  SdoFuture<uint32_t> AsyncReadDigitalInput32(int i);

  SdoFuture<uint32_t> AsyncReadDigitalInputPolarity32(int i);
  SdoFuture<void> AsyncWriteDigitalInputPolarity32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalInputFilterEnable32(int i);
  SdoFuture<void> AsyncWriteDigitalInputFilterEnable32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalInputInterruptAny32(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptAny32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalInputInterruptPositive32(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptPositive32(int i,
                                                            uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalInputInterruptNegative32(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptNegative32(int i,
                                                            uint32_t value);

  /**
   * Returns true if the additional information in the device type indicates the
   * remote node implements digital outputs, and false if not.
   */
  bool HasDigitalOutputs() const noexcept;

  uint8_t GetDigitalOutput8(int i) const;
  uint8_t GetDigitalOutput8(int i, ::std::error_code& ec) const;

  void SetDigitalOutput8(int i, uint8_t value);
  void SetDigitalOutput8(int i, uint8_t value, ::std::error_code& ec);

  SdoFuture<uint8_t> AsyncReadDigitalOutput8(int i);
  SdoFuture<void> AsyncWriteDigitalOutput8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalOutputPolarity8(int i);
  SdoFuture<void> AsyncWriteDigitalOutputPolarity8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalOutputErrorMode8(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorMode8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalOutputErrorValue8(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorValue8(int i, uint8_t value);

  SdoFuture<uint8_t> AsyncReadDigitalOutputFilterMask8(int i);
  SdoFuture<void> AsyncWriteDigitalOutputFilterMask8(int i, uint8_t value);

  bool GetDigitalOutput1(int i) const;
  bool GetDigitalOutput1(int i, ::std::error_code& ec) const;

  void SetDigitalOutput1(int i, bool value);
  void SetDigitalOutput1(int i, bool value, ::std::error_code& ec);

  SdoFuture<bool> AsyncReadDigitalOutput1(int i);
  SdoFuture<void> AsyncWriteDigitalOutput1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputPolarity1(int i);
  SdoFuture<void> AsyncWriteDigitalOutputPolarity1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputErrorMode1(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorMode1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputErrorValue1(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorValue1(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputFilterMask1(int i);
  SdoFuture<void> AsyncWriteDigitalOutputFilterMask1(int i, bool value);

  uint16_t GetDigitalOutput16(int i) const;
  uint16_t GetDigitalOutput16(int i, ::std::error_code& ec) const;

  void SetDigitalOutput16(int i, uint16_t value);
  void SetDigitalOutput16(int i, uint16_t value, ::std::error_code& ec);

  SdoFuture<uint16_t> AsyncReadDigitalOutput16(int i);
  SdoFuture<void> AsyncWriteDigitalOutput16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalOutputPolarity16(int i);
  SdoFuture<void> AsyncWriteDigitalOutputPolarity16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalOutputErrorMode16(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorMode16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalOutputErrorValue16(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorValue16(int i, uint16_t value);

  SdoFuture<uint16_t> AsyncReadDigitalOutputFilterMask16(int i);
  SdoFuture<void> AsyncWriteDigitalOutputFilterMask16(int i, uint16_t value);

  uint32_t GetDigitalOutput32(int i) const;
  uint32_t GetDigitalOutput32(int i, ::std::error_code& ec) const;

  void SetDigitalOutput32(int i, uint32_t value);
  void SetDigitalOutput32(int i, uint32_t value, ::std::error_code& ec);

  SdoFuture<uint32_t> AsyncReadDigitalOutput32(int i);
  SdoFuture<void> AsyncWriteDigitalOutput32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalOutputPolarity32(int i);
  SdoFuture<void> AsyncWriteDigitalOutputPolarity32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalOutputErrorMode32(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorMode32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalOutputErrorValue32(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorValue32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadDigitalOutputFilterMask32(int i);
  SdoFuture<void> AsyncWriteDigitalOutputFilterMask32(int i, uint32_t value);

  /**
   * Returns the locally cached value of the specified digital input line.
   *
   * @throws std::out_of_range if `i < 1 || i > 8128`.
   *
   * @pre HasDigitalInputs() returns `true`.
   */
  bool GetDigitalInput(int i) const;
  SdoFuture<bool> AsyncReadDigitalInput(int i);

  SdoFuture<bool> AsyncReadDigitalInputPolarity(int i);
  SdoFuture<void> AsyncWriteDigitalInputPolarity(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputFilterEnable(int i);
  SdoFuture<void> AsyncWriteDigitalInputFilterEnable(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptAny(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptAny(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptPositive(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptPositive(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalInputInterruptNegative(int i);
  SdoFuture<void> AsyncWriteDigitalInputInterruptNegative(int i, bool value);

  bool GetDigitalOutput(int i) const;
  bool GetDigitalOutput(int i, ::std::error_code& ec) const;

  void SetDigitalOutput(int i, bool value);
  void SetDigitalOutput(int i, bool value, ::std::error_code& ec);

  SdoFuture<bool> AsyncReadDigitalOutput(int i);
  SdoFuture<void> AsyncWriteDigitalOutput(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputPolarity(int i);
  SdoFuture<void> AsyncWriteDigitalOutputPolarity(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputErrorMode(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorMode(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputErrorValue(int i);
  SdoFuture<void> AsyncWriteDigitalOutputErrorValue(int i, bool value);

  SdoFuture<bool> AsyncReadDigitalOutputFilterMask(int i);
  SdoFuture<void> AsyncWriteDigitalOutputFilterMask(int i, bool value);

  /**
   * Returns true if the additional information in the device type indicates the
   * remote node implements analog inputs, and false if not.
   */
  bool HasAnalogInputs() const noexcept;

  int8_t GetAnalogInput8(int i) const;
  int8_t GetAnalogInput8(int i, ::std::error_code& ec) const;
  SdoFuture<int8_t> AsyncReadAnalogInput8(int i);

  int16_t GetAnalogInput16(int i) const;
  int16_t GetAnalogInput16(int i, ::std::error_code& ec) const;
  SdoFuture<int16_t> AsyncReadAnalogInput16(int i);

  int32_t GetAnalogInput32(int i) const;
  int32_t GetAnalogInput32(int i, ::std::error_code& ec) const;
  SdoFuture<int32_t> AsyncReadAnalogInput32(int i);

  float GetAnalogInputFloat(int i) const;
  float GetAnalogInputFloat(int i, ::std::error_code& ec) const;
  SdoFuture<float> AsyncReadAnalogInputFloat(int i);

  /**
   * Returns true if the additional information in the device type indicates the
   * remote node implements analog outputs, and false if not.
   */
  bool HasAnalogOutputs() const noexcept;

  int8_t GetAnalogOutput8(int i) const;
  int8_t GetAnalogOutput8(int i, ::std::error_code& ec) const;

  void SetAnalogOutput8(int i, int8_t value);
  void SetAnalogOutput8(int i, int8_t value, ::std::error_code& ec);

  SdoFuture<int8_t> AsyncReadAnalogOutput8(int i);
  SdoFuture<void> AsyncWriteAnalogOutput8(int i, int8_t value);

  int16_t GetAnalogOutput16(int i) const;
  int16_t GetAnalogOutput16(int i, ::std::error_code& ec) const;

  void SetAnalogOutput16(int i, int16_t value);
  void SetAnalogOutput16(int i, int16_t value, ::std::error_code& ec);

  SdoFuture<int16_t> AsyncReadAnalogOutput16(int i);
  SdoFuture<void> AsyncWriteAnalogOutput16(int i, int16_t value);

  int32_t GetAnalogOutput32(int i) const;
  int32_t GetAnalogOutput32(int i, ::std::error_code& ec) const;

  void SetAnalogOutput32(int i, int32_t value);
  void SetAnalogOutput32(int i, int32_t value, ::std::error_code& ec);

  SdoFuture<int32_t> AsyncReadAnalogOutput32(int i);
  SdoFuture<void> AsyncWriteAnalogOutput32(int i, int32_t value);

  float GetAnalogOutputFloat(int i) const;
  float GetAnalogOutputFloat(int i, ::std::error_code& ec) const;

  void SetAnalogOutputFloat(int i, float value);
  void SetAnalogOutputFloat(int i, float value, ::std::error_code& ec);

  SdoFuture<float> AsyncReadAnalogOutputFloat(int i);
  SdoFuture<void> AsyncWriteAnalogOutputFloat(int i, float value);

  SdoFuture<AnalogInputInterrupt> AsyncReadAnalogInputInterruptTrigger(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptTrigger(
      int i, AnalogInputInterrupt value);

  // TODO(jseldenthuis@lely.com): Add Async[...]AnalogInputInterruptSource()

  SdoFuture<bool> AsyncReadAnalogInputInterruptEnable();
  SdoFuture<void> AsyncWriteAnalogInputInterruptEnable(bool value);

  SdoFuture<int32_t> AsyncReadAnalogInputInterruptUpper32(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptUpper32(int i, int32_t value);

  SdoFuture<int32_t> AsyncReadAnalogInputInterruptLower32(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptLower32(int i, int32_t value);

  SdoFuture<uint32_t> AsyncReadAnalogInputInterruptDelta32(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptDelta32(int i, uint32_t value);

  SdoFuture<uint32_t> AsyncReadAnalogInputInterruptNegative32(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptNegative32(int i,
                                                           uint32_t value);

  SdoFuture<uint32_t> AsyncReadAnalogInputInterruptPositive32(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptPositive32(int i,
                                                           uint32_t value);

  SdoFuture<float> AsyncReadAnalogInputInterruptUpperFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptUpperFloat(int i, float value);

  SdoFuture<float> AsyncReadAnalogInputInterruptLowerFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptLowerFloat(int i, float value);

  SdoFuture<float> AsyncReadAnalogInputInterruptDeltaFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptDeltaFloat(int i, float value);

  SdoFuture<float> AsyncReadAnalogInputInterruptNegativeFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptNegativeFloat(int i,
                                                              float value);

  SdoFuture<float> AsyncReadAnalogInputInterruptPositiveFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputInterruptPositiveFloat(int i,
                                                              float value);

  SdoFuture<float> AsyncReadAnalogInputOffsetFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputOffsetFloat(int i, float value);

  SdoFuture<float> AsyncReadAnalogInputScalingFloat(int i);
  SdoFuture<void> AsyncWriteAnalogInputScalingFloat(int i, float value);

  // TODO(jseldenthuis@lely.com): Add Async[...]AnalogInputUnit()

  SdoFuture<int32_t> AsyncReadAnalogInputOffset32(int i);
  SdoFuture<void> AsyncWriteAnalogInputOffset32(int i, int32_t value);

  SdoFuture<int32_t> AsyncReadAnalogInputScaling32(int i);
  SdoFuture<void> AsyncWriteAnalogInputScaling32(int i, int32_t value);

  SdoFuture<float> AsyncReadAnalogOutputOffsetFloat(int i);
  SdoFuture<void> AsyncWriteAnalogOutputOffsetFloat(int i, float value);

  SdoFuture<float> AsyncReadAnalogOutputScalingFloat(int i);
  SdoFuture<void> AsyncWriteAnalogOutputScalingFloat(int i, float value);

  SdoFuture<bool> AsyncReadAnalogOutputErrorMode(int i);
  SdoFuture<void> AsyncWriteAnalogOutputErrorMode(int i, bool value);

  SdoFuture<int32_t> AsyncReadAnalogOutputErrorValue32(int i);
  SdoFuture<void> AsyncWriteAnalogOutputErrorValue32(int i, int32_t value);

  SdoFuture<float> AsyncReadAnalogOutputErrorValueFloat(int i);
  SdoFuture<void> AsyncWriteAnalogOutputErrorValueFloat(int i, float value);

  SdoFuture<int32_t> AsyncReadAnalogOutputOffset32(int i);
  SdoFuture<void> AsyncWriteAnalogOutputOffset32(int i, int32_t value);

  SdoFuture<int32_t> AsyncReadAnalogOutputScaling32(int i);
  SdoFuture<void> AsyncWriteAnalogOutputScaling32(int i, int32_t value);

  // TODO(jseldenthuis@lely.com): Add Async[...]AnalogOutputUnit()

 protected:
  void OnRpdoWrite(uint16_t idx, uint8_t subidx) noexcept override;

  virtual void
  OnDigitalInput8(int /*i*/, uint8_t /*value*/) noexcept {}
  virtual void
  OnDigitalInput1(int /*i*/, bool /*value*/) noexcept {}
  virtual void
  OnDigitalInput16(int /*i*/, uint16_t /*value*/) noexcept {}
  virtual void
  OnDigitalInput32(int /*i*/, uint32_t /*value*/) noexcept {}

  virtual void
  OnDigitalInput(int /*i*/, bool /*value*/) noexcept {}

  virtual void
  OnAnalogInput8(int /*i*/, int8_t /*value*/) noexcept {}
  virtual void
  OnAnalogInput16(int /*i*/, int16_t /*value*/) noexcept {}
  virtual void
  OnAnalogInput32(int /*i*/, int32_t /*value*/) noexcept {}
  virtual void
  OnAnalogInputFloat(int /*i*/, float /*value*/) noexcept {}

 private:
  struct Impl_;
  ::std::unique_ptr<Impl_> impl_;
};

constexpr AnalogInputInterrupt
operator~(AnalogInputInterrupt rhs) {
  return static_cast<AnalogInputInterrupt>(~static_cast<uint8_t>(rhs));
}

constexpr AnalogInputInterrupt operator&(AnalogInputInterrupt lhs,
                                         AnalogInputInterrupt rhs) {
  return static_cast<AnalogInputInterrupt>(static_cast<uint8_t>(lhs) &
                                           static_cast<uint8_t>(rhs));
}

constexpr AnalogInputInterrupt
operator^(AnalogInputInterrupt lhs, AnalogInputInterrupt rhs) {
  return static_cast<AnalogInputInterrupt>(static_cast<uint8_t>(lhs) ^
                                           static_cast<uint8_t>(rhs));
}

constexpr AnalogInputInterrupt
operator|(AnalogInputInterrupt lhs, AnalogInputInterrupt rhs) {
  return static_cast<AnalogInputInterrupt>(static_cast<uint8_t>(lhs) |
                                           static_cast<uint8_t>(rhs));
}

inline AnalogInputInterrupt&
operator&=(AnalogInputInterrupt& lhs, AnalogInputInterrupt rhs) {
  return lhs = lhs & rhs;
}

inline AnalogInputInterrupt&
operator^=(AnalogInputInterrupt& lhs, AnalogInputInterrupt rhs) {
  return lhs = lhs ^ rhs;
}

inline AnalogInputInterrupt&
operator|=(AnalogInputInterrupt& lhs, AnalogInputInterrupt rhs) {
  return lhs = lhs | rhs;
}

}  // namespace canopen

}  // namespace lely

#endif  // !LELY_COAPP_DRIVERS_401_HPP_
