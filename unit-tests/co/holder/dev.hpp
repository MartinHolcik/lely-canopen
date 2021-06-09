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

#ifndef LELY_UNIT_TESTS_CO_DEV_HOLDER_HPP_
#define LELY_UNIT_TESTS_CO_DEV_HOLDER_HPP_

#include <memory>

#include <CppUTest/TestHarness.h>

#include <lely/co/dev.h>

#if LELY_NO_MALLOC
#include <lely/co/detail/dev.h>
#endif

#include "holder.hpp"
#include "obj.hpp"

class CoDevTHolder : public Holder<co_dev_t> {
 public:
#if LELY_NO_MALLOC
  explicit CoDevTHolder(co_unsigned8_t id) { co_dev_init(Get(), id); }
#else   // !LELY_NO_MALLOC
  explicit CoDevTHolder(co_unsigned8_t id)
      : Holder<co_dev_t>(co_dev_create(id)) {}

  ~CoDevTHolder() {
    if (!taken) co_dev_destroy(Get());
  }
#endif  // LELY_NO_MALLOC

  void
  CreateAndInsertObj(std::unique_ptr<CoObjTHolder>& obj_holder,
                     const co_unsigned16_t idx) {
    obj_holder.reset(new CoObjTHolder(idx));
    CHECK(obj_holder->Get() != nullptr);
    CHECK_EQUAL(0, co_dev_insert_obj(Get(), obj_holder->Take()));
  }
};  // class CoDevTHolder

#endif  // LELY_UNIT_TESTS_CO_DEV_HOLDER_HPP_
