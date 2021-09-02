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

#ifndef LELY_UNIT_TESTS_CPPUTEST_EXT_HPP_
#define LELY_UNIT_TESTS_CPPUTEST_EXT_HPP_

#include <cassert>

/**
 * A group of handy CppUTest-style macros to handle calling base test group's
 * setup() and teardown() functions. To utilize them one should first put
 * TEST_BASE_SETUP() in a base group with the group name as a parameter. Then
 * in sub-groups TEST_BASE_SETUP() and TEST_BASE_TEARDOWN() can be used to
 * call respective functions.
 */
#define TEST_BASE_SUPER(base) using super = base
#define TEST_BASE_SETUP() super::setup()
#define TEST_BASE_TEARDOWN() super::teardown()

// scan-build reports a null dereference on pointers checked by
// `CHECK(ptr != nullptr)` due to not recognizing it as a no-return
// function - below macros add an explicit assert() to fix this issue
// see: https://clang-analyzer.llvm.org/faq.html#custom_assert
#define POINTER_NOT_NULL(ptr) \
  do { \
    const void* const ptr_val = (ptr); \
    CHECK(ptr_val != nullptr); \
    assert(ptr_val); \
  } while (false)

#define FUNCTIONPOINTER_NOT_NULL(ptr) \
  do { \
    auto* const ptr_val = (ptr); \
    static_assert( \
        std::is_function< \
            typename std::remove_pointer<decltype(ptr_val)>::type>::value, \
        "FUNCTIONPOINTER_NOT_NULL(): 'ptr' is not a function pointer"); \
    CHECK(ptr_val != nullptr); \
    assert(ptr_val); \
  } while (false)

// utility macro to quickly check if given memory area contains only zeroes
#define MEMORY_IS_ZEROED(ptr, size) \
  do { \
    const uint_least8_t zeroes[(size)] = {0}; \
    MEMCMP_EQUAL(zeroes, (ptr), (size)); \
  } while (false)

#endif  // LELY_UNIT_TESTS_CPPUTEST_EXT_HPP_
