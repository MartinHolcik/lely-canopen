/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the network address declarations.
 *
 * @see lely/io2/addr.h
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

#ifndef LELY_IO2_ADDR_HPP_
#define LELY_IO2_ADDR_HPP_

#include <lely/io2/addr.h>

#include <typeinfo>
#include <type_traits>
#include <utility>

namespace lely {
namespace io {

/// The exception thrown when a network address cast fails.
class bad_address_cast : public ::std::bad_cast {};

template <class T>
const T* address_cast(const io_addr* addr);

template <class T>
T* address_cast(io_addr* addr);

template <class T>
inline T
address_cast(const io_addr& addr) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(*address_cast<U>(&addr));
}

template <class T>
inline T
address_cast(io_addr& addr) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(*address_cast<U>(&addr));
}

template <class T>
inline T
address_cast(io_addr&& addr) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(::std::move(*address_cast<U>(&addr)));
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_ADDR_HPP_
