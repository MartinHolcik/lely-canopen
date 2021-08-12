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

#ifndef LELY_UNIT_TESTS_CO_OBJ_HOLDER_HPP_
#define LELY_UNIT_TESTS_CO_OBJ_HOLDER_HPP_

#include <cassert>
#include <cstring>
#include <memory>
#include <vector>

#include <CppUTest/TestHarness.h>

#include <lely/co/obj.h>
#include <lely/co/val.h>

#if LELY_NO_MALLOC
#include <lely/co/detail/obj.h>
#endif

#include "holder.hpp"
#include "sub.hpp"
#include "obj-init/obj-init.hpp"

/// Wrapper for #co_obj_t that separates unit-tests from memory allocation.
/// Allows for the same unit tests to run with dynamic allocation disabled or
/// enabled.
class CoObjTHolder : public Holder<co_obj_t> {
#if LELY_NO_MALLOC

 public:
  explicit CoObjTHolder(const co_unsigned16_t idx) {
    co_obj_init(Get(), idx, val_data, 0);
  }

  static const size_t PREALLOCATED_OBJ_SIZE = 768u;

 private:
  char val_data[PREALLOCATED_OBJ_SIZE] = {0};
#else   // !LELY_NO_MALLOC

 public:
  explicit CoObjTHolder(const co_unsigned16_t idx)
      : Holder<co_obj_t>(co_obj_create(idx)) {}

  ~CoObjTHolder() {
    if (!taken) co_obj_destroy(Get());
  }
#endif  // LELY_NO_MALLOC

 public:
  /**
   * Inserts a sub-object into a CANopen object taking the ownership of the
   * sub-object pointer. On error sub-object holder retains ownership of the
   * pointer. Method will assert if object's value memory capacity is exceeded.
   *
   * @param sub_holder a holder of the sub-object to be inserted.
   *
   * @returns a pointer to the inserted sub-object on success, or nullptr on
   * error.
   */
  co_sub_t*
  InsertSub(CoSubTHolder& sub_holder) {
    if (co_obj_insert_sub(Get(), sub_holder.Get()) != 0) return nullptr;

    auto* const taken_sub = sub_holder.Take();
    UpdateSubValues();

    return taken_sub;
  }

  /**
   * Construct a sub-object, insert it into a CANopen object and set its value.
   * Sub-object's holder is stored inside object's holder and can be accessed
   * with GetSubs() method.
   *
   * @param subidx the object sub-index.
   * @param type   the data type of the sub-object value (in the range [1..27]).
   *               This MUST be the object index of one of the static data
   *               types.
   * @param val    the sub-object's value.
   */
  template <class T>
  void
  InsertAndSetSub(const co_unsigned8_t subidx, const co_unsigned16_t type,
                  const T val) {
    assert(sizeof(T) == co_type_sizeof(type));

    sub_holders.push_back(
        std::unique_ptr<CoSubTHolder>(new CoSubTHolder(subidx, type)));

    auto* const sub = InsertSub(*sub_holders.back().get());
    CHECK(sub != nullptr);

    CHECK_EQUAL(co_type_sizeof(type), co_sub_set_val(sub, &val, sizeof(val)));
  }

  /**
   * Get the reference on sub-objects container.
   */
  std::vector<std::unique_ptr<CoSubTHolder>>&
  GetSubs() {
    return sub_holders;
  }

  /**
   * Get the pointer to the last added sub-object.
   */
  co_sub_t*
  GetLastSub() {
    return sub_holders.back()->Get();
  }

  /**
   * Remove the last added sub-object
   */
  bool
  RemoveAndDestroyLastSub() {
    const auto ret = co_obj_remove_sub(Get(), GetLastSub());
    if (ret != 0) return false;

    POINTERS_EQUAL(GetLastSub(), sub_holders.back()->Reclaim());
    sub_holders.pop_back();
    UpdateSubValues();

    return true;
  }

  /**
   * Construct and insert a CANopen sub-object with a given sub-index and
   * value, based on and checked against meta-information from a template type.
   *
   * @see ObjInitT::SubT
   */
  template <typename T>
  void
  EmplaceSub(const co_unsigned8_t subidx, const typename T::sub_type val) {
    assert(T::min_subidx > 0 ? subidx >= T::min_subidx : subidx == T::subidx);
    assert(co_obj_get_idx(Get()) >= T::min_idx &&
           co_obj_get_idx(Get()) <= T::max_idx);
    assert(co_obj_find_sub(Get(), subidx) == nullptr);

    InsertAndSetSub(subidx, T::deftype, val);
  }

  /**
   * Construct and insert a CANopen sub-object with a given value, based on and
   * checked against meta-information from a template type.
   *
   * @see ObjInitT::SubT
   */
  template <typename T>
  void
  EmplaceSub(const typename T::sub_type val = T::default_val) {
    EmplaceSub<T>(T::subidx, val);
  }

  /**
   * Sets the current value of a CANopen sub-object with a given sub-index,
   * based on and checked against meta-information from a template type.
   *
   * @see ObjInitT::SubT
   */
  template <typename T>
  void
  SetSub(const co_unsigned8_t subidx, const typename T::sub_type val) {
    assert(T::min_subidx > 0 ? subidx >= T::min_subidx : subidx == T::subidx);
    assert(co_obj_get_idx(Get()) >= T::min_idx &&
           co_obj_get_idx(Get()) <= T::max_idx);
    assert(co_obj_find_sub(Get(), subidx) != nullptr);

    CHECK_EQUAL(co_type_sizeof(T::deftype),
                co_obj_set_val(Get(), subidx, &val, sizeof(val)));
  }

  /**
   * Sets the current value of a CANopen sub-object, based on and checked
   * against meta-information from a template type.
   *
   * @see ObjInitT::SubT
   */
  template <typename T>
  void
  SetSub(const typename T::sub_type val) {
    SetSub<T>(T::subidx, val);
  }

  /**
   * Gets the current value of a CANopen sub-object with the given sub-index,
   * based on and checked against meta-information from a template type.
   *
   * @see ObjInitT::SubT
   */
  template <typename T>
  typename T::sub_type
  GetSub(const co_unsigned8_t subidx = T::subidx) {
    assert(T::min_subidx > 0 ? subidx >= T::min_subidx : subidx == T::subidx);
    assert(co_obj_get_idx(Get()) >= T::min_idx &&
           co_obj_get_idx(Get()) <= T::max_idx);
    assert(co_obj_find_sub(Get(), subidx) != nullptr);

    typename T::sub_type val = 0;
    const void* const val_ptr = co_obj_get_val(Get(), subidx);

    co_val_copy(T::deftype, &val, val_ptr);

    return val;
  }

 protected:
  void
  UpdateSubValues() {
#if LELY_NO_MALLOC
    // Calculate capacity needed for sub-object values.
    size_t size = 0;
    rbtree_foreach(&Get()->tree, node) {
      const co_sub_t* const sub = structof(node, co_sub_t, node);
      const co_unsigned16_t type = co_sub_get_type(sub);
      size = ALIGN(size, co_type_alignof(type));
      size += co_type_sizeof(type);
    }
    assert(size <= PREALLOCATED_OBJ_SIZE);

    // Make a copy of all values' data.
    char old_data[PREALLOCATED_OBJ_SIZE] = {0};
    memcpy(old_data, val_data, PREALLOCATED_OBJ_SIZE);
    memset(val_data, 0, PREALLOCATED_OBJ_SIZE);

    // Rearrange values in the value data memory.
    size = 0;
    rbtree_foreach(&Get()->tree, node) {
      co_sub_t* const sub = structof(node, co_sub_t, node);
      const co_unsigned16_t type = co_sub_get_type(sub);

      // Compute the offset of the sub-object.
      size = ALIGN(size, co_type_alignof(type));

      // Move the old value, if it exists.
      auto src = static_cast<char*>(sub->val);
      sub->val = val_data + size;
      if (src != nullptr) {
        const ssize_t DATA_MAX_OFFSET = PREALLOCATED_OBJ_SIZE;
        const auto offset = src - val_data;
        // If value was located within 'val_data', update the 'src' pointer
        // as value has been moved to 'old_data'.
        if ((offset >= 0) && (offset < DATA_MAX_OFFSET))
          src = old_data + offset;

        co_val_move(type, sub->val, src);
      }
      size += co_type_sizeof(type);
    }
    Get()->size = size;
#endif
  }

 private:
  std::vector<std::unique_ptr<CoSubTHolder>> sub_holders;
};  // class CoObjTHolder

#endif  // LELY_UNIT_TESTS_CO_OBJ_HOLDER_HPP_
