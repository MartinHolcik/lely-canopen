/**@file
 * This file is part of the CANopen Library Unit Test Suite.
 *
 * @copyright 2021 N7 Space Sp. z o.o.
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

#ifndef LELY_UNIT_TEST_REQUEST_NMT_HPP_
#define LELY_UNIT_TEST_REQUEST_NMT_HPP_

#include "obj-init/obj-init.hpp"

#include <lely/co/dev.h>

/// 0x1f82: Request NMT
struct Obj1f82RequestNmt : ObjInitT<0x1f82u> {
  struct Sub00SupportedNumberOfSlaves : SubT<0x00u, CO_DEFTYPE_UNSIGNED8> {};
  struct SubNthRequestNmtService : SubT<0x01u, CO_DEFTYPE_UNSIGNED8, 0, 0x01> {
  };

  static const co_unsigned8_t ALL_NODES = 0x80u;
};

#endif  // LELY_UNIT_TEST_REQUEST_NMT_HPP_
