/**@file
 * This file is part of the CANopen Library Unit Test Suite.
 *
 * @copyright 2020-2021 N7 Space Sp. z o.o.
 *
 * Unit Test Suite was developed under a programme of,
 * and funded by, the European Space Agency.
 *
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
#ifndef LELY_UNIT_TEST_HPP_
#define LELY_UNIT_TEST_HPP_

#include <lely/can/msg.h>
#include <lely/co/type.h>
#include <lely/util/endian.h>

#define CHECK_SDO_CAN_MSG_CMD(res, msg) CHECK_EQUAL((res), (msg)[0])
#define CHECK_SDO_CAN_MSG_IDX(idx, msg) CHECK_EQUAL((idx), ldle_u16((msg) + 1u))
#define CHECK_SDO_CAN_MSG_SUBIDX(subidx, msg) CHECK_EQUAL((subidx), (msg)[3u])
#define CHECK_SDO_CAN_MSG_AC(ac, msg) CHECK_EQUAL((ac), ldle_u32((msg) + 4u))
#define CHECK_SDO_CAN_MSG_VAL(val, msg) CHECK_EQUAL((val), ldle_u32((msg) + 4u))

namespace LelyUnitTest {
/**
 * Sets empty handlers for all diagnostic messages from lely-core library.
 *
 * @see diag_set_handler(), diag_at_set_handler()
 */
void DisableDiagnosticMessages();

/**
 * Checks if a download indication function is set (not null) for
 * a sub-object with the given user-specifed data pointer.
 */
void CheckSubDnIndIsSet(const co_dev_t* dev, co_unsigned16_t idx,
                        const void* data);
/**
 * Checks if sub-object has a default download indication function and
 * user-specified data set.
 */
void CheckSubDnIndIsDefault(const co_dev_t* dev, co_unsigned16_t idx);

/**
  * Calls the download indication function for the sub-object with the given
  * abort code.
  */
co_unsigned32_t CallDnIndWithAbortCode(const co_dev_t* dev, co_unsigned16_t idx,
                                       co_unsigned8_t subidx,
                                       co_unsigned32_t ac);

}  // namespace LelyUnitTest

struct CoCsdoDnCon {
  static co_csdo_t* sdo;
  static co_unsigned16_t idx;
  static co_unsigned8_t subidx;
  static co_unsigned32_t ac;
  static void* data;
  static unsigned int num_called;

  static void func(co_csdo_t* sdo_, co_unsigned16_t idx_,
                   co_unsigned8_t subidx_, co_unsigned32_t ac_, void* data_);
  static void Check(const co_csdo_t* sdo_, co_unsigned16_t idx_,
                    co_unsigned8_t subidx_, co_unsigned32_t ac_,
                    const void* data_);
  static void Clear();

  static inline bool
  Called() {
    return num_called > 0;
  }
};

struct CoCsdoUpCon {
  static co_csdo_t* sdo;
  static co_unsigned16_t idx;
  static co_unsigned8_t subidx;
  static co_unsigned32_t ac;
  static const void* ptr;
  static size_t n;
  static void* data;
  static unsigned int num_called;
  static constexpr size_t BUFSIZE = 2u;
  static uint_least8_t buf[BUFSIZE];

  static void func(co_csdo_t* sdo_, co_unsigned16_t idx_,
                   co_unsigned8_t subidx_, co_unsigned32_t ac_,
                   const void* ptr_, size_t n_, void* data_);
  static void Check(const co_csdo_t* sdo_, co_unsigned16_t idx_,
                    co_unsigned8_t subidx_, co_unsigned32_t ac_,
                    const void* ptr_, size_t n_, const void* data_);
  static void CheckNonempty(const co_csdo_t* sdo_, co_unsigned16_t idx_,
                            co_unsigned8_t subidx_, co_unsigned32_t ac_,
                            size_t n_, const void* data_);
  static void Clear();

  static inline bool
  Called() {
    return num_called > 0;
  }
};

struct CanSend {
 private:
  static size_t buf_size;

 public:
  static int ret;
  static void* data;
  static unsigned int num_called;
  static can_msg msg;
  static can_msg* msg_buf;

  static int func(const can_msg* msg_, void* data_);
  static void CheckMsg(uint_least32_t id, uint_least8_t flags,
                       uint_least8_t len, const uint_least8_t* data);
  static void CheckSdoMsg(co_unsigned32_t id_, co_unsigned32_t flags_,
                          uint_least8_t len_, co_unsigned8_t cs_,
                          co_unsigned16_t idx_, co_unsigned8_t subidx_,
                          co_unsigned32_t ac_);
  static void Clear();

  static inline bool
  Called() {
    return num_called > 0;
  }

  /**
   * Sets a message buffer.
   *
   * @param buf a pointer to a CAN message buffer.
   * @param size the number of frames available at <b>buf</b>.
   */
  static inline void
  SetMsgBuf(can_msg* const buf, const size_t size) {
    buf_size = size;
    msg_buf = buf;
  }
};

#endif  // LELY_UNIT_TEST_HPP_