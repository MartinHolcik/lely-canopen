/**@file
 * This header file is part of the I/O library; it contains the C++ interface
 * for the network protocol endpoint declarations.
 *
 * @see lely/io2/endp.h
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

#ifndef LELY_IO2_ENDP_HPP_
#define LELY_IO2_ENDP_HPP_

#include <lely/io2/addr.hpp>
#include <lely/io2/endp.h>

#include <utility>

namespace lely {
namespace io {

/// The exception thrown when a network protocol endpoint cast fails.
class bad_endpoint_cast : public ::std::bad_cast {};

/**
 * An network endpoint large enough to accommodate all supported
 * protocol-specific endpoints.
 */
class Endpoint : public io_endp_storage {
 public:
  Endpoint() noexcept : io_endp_storage IO_ENDP_STORAGE_INIT {}

  Endpoint(const Endpoint&) = delete;
  Endpoint& operator=(const Endpoint&) = delete;

  Endpoint& operator=(const io_endp_storage&) = delete;

  operator io_endp*() noexcept { return reinterpret_cast<io_endp*>(this); }

  operator const io_endp*() const noexcept {
    return reinterpret_cast<const io_endp*>(this);
  }
};

template <class T>
const T* endpoint_cast(const io_endp* endp);

template <class T>
T* endpoint_cast(io_endp* endp);

template <class T>
inline T
endpoint_cast(const io_endp& endp) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(*endpoint_cast<U>(&endp));
}

template <class T>
inline T
endpoint_cast(io_endp& endp) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(*endpoint_cast<U>(&endp));
}

template <class T>
inline T
endpoint_cast(io_endp&& endp) {
  using U = typename ::std::remove_cv<
      typename ::std::remove_reference<T>::type>::type;
  return static_cast<T>(::std::move(*endpoint_cast<U>(&endp)));
}

}  // namespace io
}  // namespace lely

#endif  // !LELY_IO2_ENDP_HPP_
