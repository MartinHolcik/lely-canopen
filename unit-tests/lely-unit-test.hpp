/**@file
 * This file is part of the CANopen Library Unit Test Suite.
 *
 * @copyright 2020 N7 Space Sp. z o.o.
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

#include <lely/co/type.h>
#include <lely/util/diag.h>

namespace LelyUnitTest {
/**
 * Set empty handlers for all diagnostic messages from lely-core library.
 *
 * @see diag_set_handler(), diag_at_set_handler()
 */
inline void
DisableDiagnosticMessages() {
  diag_set_handler(nullptr, nullptr);
  diag_at_set_handler(nullptr, nullptr);
}
}  // namespace LelyUnitTest

struct CoCsdoDnCon {
  static co_csdo_t* sdo;
  static co_unsigned16_t idx;
  static co_unsigned8_t subidx;
  static co_unsigned32_t ac;
  static void* data;
  static bool called;

  static inline void
  func(co_csdo_t* sdo_, co_unsigned16_t idx_, co_unsigned8_t subidx_,
       co_unsigned32_t ac_, void* data_) {
    sdo = sdo_;
    idx = idx_;
    subidx = subidx_;
    ac = ac_;
    data = data_;
    called = true;
  }

  static void inline Clear() {
    sdo = nullptr;
    idx = 0;
    subidx = 0;
    ac = 0;
    data = nullptr;

    called = false;
  }
};

#endif  // LELY_UNIT_TEST_HPP_