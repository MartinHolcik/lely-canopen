/**@file
 * This header file is part of the utilities library; it contains the C++
 * interface for the random number generator.
 *
 * @copyright 2015-2020 Lely Industries N.V.
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

#ifndef LELY_UTIL_RAND_HPP_
#define LELY_UTIL_RAND_HPP_

#include <lely/util/rand.h>

#include <limits>

namespace lely {
namespace util {

template <class>
class Rand;

template <>
class Rand<uint_least8_t> {
 public:
  using result_type = uint_least8_t;

  static constexpr result_type
  min() {
    return ::std::numeric_limits<result_type>::min();
  }

  static constexpr result_type
  max() {
    return ::std::numeric_limits<result_type>::max();
  }

  static constexpr result_type default_seed = 0;

  Rand() noexcept : Rand(default_seed) {}

  explicit Rand(result_type s) noexcept { seed(s); }

  template <class Sseq>
  explicit Rand(Sseq& q) {
    seed(q);
  }

  /// @see rand_u8_seed()
  void
  seed(result_type s = default_seed) noexcept {
    rand_u8_seed(&r_, s);
  }

  template <class Sseq>
  void
  seed(Sseq& q) {
    uint_least32_t a[2];
    q.generate(a, a + 2);
    seed((static_cast<uint_least64_t>(a[0]) << 32) | a[1]);
  }

  /// @see rand_u8_get()
  result_type
  operator()() noexcept {
    return rand_u8_get(&r_);
  }

  /// @see rand_u8_discard()
  void
  discard(unsigned long long z) noexcept {  // NOLINT(runtime/int)
    rand_u8_discard(&r_, z);
  }

 private:
  rand_u8_t r_;
};

template <>
class Rand<uint_least16_t> {
 public:
  using result_type = uint_least16_t;

  static constexpr result_type
  min() {
    return ::std::numeric_limits<result_type>::min();
  }

  static constexpr result_type
  max() {
    return ::std::numeric_limits<result_type>::max();
  }

  static constexpr result_type default_seed = 0;

  Rand() noexcept : Rand(default_seed) {}

  explicit Rand(result_type s) noexcept { seed(s); }

  template <class Sseq>
  explicit Rand(Sseq& q) {
    seed(q);
  }

  /// @see rand_u16_seed()
  void
  seed(result_type s = default_seed) noexcept {
    rand_u16_seed(&r_, s);
  }

  template <class Sseq>
  void
  seed(Sseq& q) {
    uint_least32_t a[2];
    q.generate(a, a + 2);
    seed((static_cast<uint_least64_t>(a[0]) << 32) | a[1]);
  }

  /// @see rand_u16_get()
  result_type
  operator()() noexcept {
    return rand_u16_get(&r_);
  }

  /// @see rand_u16_discard()
  void
  discard(unsigned long long z) noexcept {  // NOLINT(runtime/int)
    rand_u16_discard(&r_, z);
  }

 private:
  rand_u16_t r_;
};

template <>
class Rand<uint_least32_t> {
 public:
  using result_type = uint_least32_t;

  static constexpr result_type
  min() {
    return ::std::numeric_limits<result_type>::min();
  }

  static constexpr result_type
  max() {
    return ::std::numeric_limits<result_type>::max();
  }

  static constexpr result_type default_seed = 0;

  Rand() noexcept : Rand(default_seed) {}

  explicit Rand(result_type s) noexcept { seed(s); }

  template <class Sseq>
  explicit Rand(Sseq& q) {
    seed(q);
  }

  /// @see rand_u32_seed()
  void
  seed(result_type s = default_seed) noexcept {
    rand_u32_seed(&r_, s);
  }

  template <class Sseq>
  void
  seed(Sseq& q) {
    uint_least32_t a[2];
    q.generate(a, a + 2);
    seed((static_cast<uint_least64_t>(a[0]) << 32) | a[1]);
  }

  /// @see rand_u32_get()
  result_type
  operator()() noexcept {
    return rand_u32_get(&r_);
  }

  /// @see rand_u32_discard()
  void
  discard(unsigned long long z) noexcept {  // NOLINT(runtime/int)
    rand_u32_discard(&r_, z);
  }

 private:
  rand_u32_t r_;
};

template <>
class Rand<uint_least64_t> {
 public:
  using result_type = uint_least64_t;

  static constexpr result_type
  min() {
    return ::std::numeric_limits<result_type>::min();
  }

  static constexpr result_type
  max() {
    return ::std::numeric_limits<result_type>::max();
  }

  static constexpr result_type default_seed = 0;

  Rand() noexcept : Rand(default_seed) {}

  explicit Rand(result_type s) noexcept { seed(s); }

  template <class Sseq>
  explicit Rand(Sseq& q) {
    seed(q);
  }

  /// @see rand_u64_seed()
  void
  seed(result_type s = default_seed) noexcept {
    rand_u64_seed(&r_, s);
  }

  template <class Sseq>
  void
  seed(Sseq& q) {
    uint_least32_t a[2];
    q.generate(a, a + 2);
    seed((static_cast<uint_least64_t>(a[0]) << 32) | a[1]);
  }

  /// @see rand_u64_get()
  result_type
  operator()() noexcept {
    return rand_u64_get(&r_);
  }

  /// @see rand_u64_discard()
  void
  discard(unsigned long long z) noexcept {  // NOLINT(runtime/int)
    rand_u64_discard(&r_, z);
  }

 private:
  rand_u64_t r_;
};

}  // namespace util
}  // namespace lely

#endif  // LELY_UTIL_RAND_HPP_
