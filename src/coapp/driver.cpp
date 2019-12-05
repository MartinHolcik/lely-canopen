/**@file
 * This file is part of the C++ CANopen application library; it contains the
 * implementation of the remote node and logical device driver interface.
 *
 * @see lely/coapp/driver.hpp
 *
 * @copyright 2018-2019 Lely Industries N.V.
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

#include "coapp.hpp"

#if !LELY_NO_COAPP_MASTER

#include <lely/coapp/driver.hpp>

#include <string>
#include <vector>

namespace lely {

namespace canopen {

BasicDriver::BasicDriver(ev_exec_t* exec, BasicMaster& master_, uint8_t id)
    : master(master_),
      rpdo_mapped(master.RpdoMapped(id)),
      tpdo_mapped(master.TpdoMapped(id)),
      tpdo_event_mutex(master.tpdo_event_mutex),
      exec_(exec),
      id_(id) {
  master.Insert(*this);
}

BasicDriver::~BasicDriver() { master.Erase(*this); }

void
BasicDriver::Insert(LogicalDriverBase& driver) {
  if (driver.Number() < 1 || driver.Number() > 8)
    throw ::std::out_of_range("invalid logical device number: " +
                              ::std::to_string(driver.Number()));
  if (find(driver.id()) != end())
    throw ::std::out_of_range("logical device number " +
                              ::std::to_string(driver.Number()) +
                              " already registered");

  MapType::operator[](driver.Number()) = &driver;
}

void
BasicDriver::Erase(LogicalDriverBase& driver) {
  auto it = find(driver.Number());
  if (it != end() && it->second == &driver) erase(it);
}

SdoFuture<void>
BasicDriver::AsyncConfig(int num) {
  if (num) {
    auto it = find(num);
    if (it != end()) return it->second->AsyncConfig();
  } else if (size() == 1) {
    // Shortcut in case of a single logical device.
    return begin()->second->AsyncConfig();
  } else if (!empty()) {
    ::std::vector<SdoFuture<void>> futures;
    // Post an OnConfig() task for each logical device driver.
    for (const auto& it : *this) futures.push_back(it.second->AsyncConfig());
    // Create a future which becomes ready when all OnConfig() tasks have
    // finished.
    return ev::when_all(GetExecutor(), futures.begin(), futures.end())
        // Check the results of the tasks.
        .then(GetExecutor(), [futures](ev::Future<::std::size_t, void>) {
          for (const auto& it : futures) {
            // Throw an exception in an error occurred.
            it.get().value();
          }
        });
  }
  return make_empty_sdo_future();
}

SdoFuture<void>
BasicDriver::AsyncDeconfig(int num) {
  if (num) {
    auto it = find(num);
    if (it != end()) return it->second->AsyncDeconfig();
  } else if (size() == 1) {
    // Shortcut in case of a single logical device.
    return begin()->second->AsyncConfig();
  } else if (!empty()) {
    ::std::vector<SdoFuture<void>> futures;
    // Post an OnConfig() task for each logical device driver.
    for (const auto& it : *this) futures.push_back(it.second->AsyncConfig());
    // Create a future which becomes ready when all OnDeconfig() tasks have
    // finished.
    return ev::when_all(GetExecutor(), futures.begin(), futures.end())
        // Check the results of the tasks.
        .then(GetExecutor(), [futures](ev::Future<::std::size_t, void>) {
          for (const auto& it : futures) {
            // Throw an exception in an error occurred.
            it.get().value();
          }
        });
  }
  return make_empty_sdo_future();
}

void
BasicDriver::OnCanState(io::CanState new_state,
                        io::CanState old_state) noexcept {
  for (const auto& it : *this) it.second->OnCanState(new_state, old_state);
}

void
BasicDriver::OnCanError(io::CanError error) noexcept {
  for (const auto& it : *this) it.second->OnCanError(error);
}

void
BasicDriver::OnRpdoWrite(uint16_t idx, uint8_t subidx) noexcept {
  if (idx >= 0x6000 && idx <= 0x9fff) {
    int num = (idx - 0x6000) / 0x800 + 1;
    auto it = find(num);
    if (it != end()) it->second->OnRpdoWrite(idx - (num - 1) * 0x800, subidx);
  } else {
    for (const auto& it : *this) it.second->OnRpdoWrite(idx, subidx);
  }
}

void
BasicDriver::OnCommand(NmtCommand cs) noexcept {
  for (const auto& it : *this) it.second->OnCommand(cs);
}

void
BasicDriver::OnNodeGuarding(bool occurred) noexcept {
  for (const auto& it : *this) it.second->OnNodeGuarding(occurred);
}

void
BasicDriver::OnHeartbeat(bool occurred) noexcept {
  for (const auto& it : *this) it.second->OnHeartbeat(occurred);
}

void
BasicDriver::OnState(NmtState st) noexcept {
  for (const auto& it : *this) it.second->OnState(st);
}

void
BasicDriver::OnBoot(NmtState st, char es, const ::std::string& what) noexcept {
  for (const auto& it : *this) it.second->OnBoot(st, es, what);
}

void
BasicDriver::OnConfig(
    ::std::function<void(::std::error_code ec)> res) noexcept {
  if (empty()) {
    // Shortcut if no logical device drivers have been registered.
    res(::std::error_code{});
  } else {
    try {
      auto f = AsyncConfig();
      // Invoke res() when AsyncConfig() completes.
      f.submit(GetExecutor(), [res, f] {
        // Extract the error code from the exception pointer, if any.
        ::std::error_code ec;
        auto& result = f.get();
        if (result.has_error()) {
          try {
            ::std::rethrow_exception(result.error());
          } catch (const ::std::system_error& e) {
            ec = e.code();
          } catch (...) {
            // Ignore exceptions we cannot handle.
          }
        }
        res(ec);
      });
    } catch (::std::system_error& e) {
      res(e.code());
    }
  }
}

void
BasicDriver::OnDeconfig(
    ::std::function<void(::std::error_code ec)> res) noexcept {
  if (empty()) {
    // Shortcut if no logical device drivers have been registered.
    res(::std::error_code{});
  } else {
    try {
      auto f = AsyncDeconfig();
      // Invoke res() when AsyncConfig() completes.
      f.submit(GetExecutor(), [res, f] {
        // Extract the error code from the exception pointer, if any.
        ::std::error_code ec;
        auto& result = f.get();
        if (result.has_error()) {
          try {
            ::std::rethrow_exception(result.error());
          } catch (const ::std::system_error& e) {
            ec = e.code();
          } catch (...) {
            // Ignore exceptions we cannot handle.
          }
        }
        res(ec);
      });
    } catch (::std::system_error& e) {
      res(e.code());
    }
  }
}

void
BasicDriver::OnSync(uint8_t cnt, const time_point& t) noexcept {
  for (const auto& it : *this) it.second->OnSync(cnt, t);
}

void
BasicDriver::OnSyncError(uint16_t eec, uint8_t er) noexcept {
  for (const auto& it : *this) it.second->OnSyncError(eec, er);
}

void
BasicDriver::OnTime(
    const ::std::chrono::system_clock::time_point& abs_time) noexcept {
  for (const auto& it : *this) it.second->OnTime(abs_time);
}

void
BasicDriver::OnEmcy(uint16_t eec, uint8_t er, uint8_t msef[5]) noexcept {
  for (const auto& it : *this) it.second->OnEmcy(eec, er, msef);
}

BasicLogicalDriver::BasicLogicalDriver(BasicDriver& driver_, int num,
                                       uint32_t dev)
    : master(driver_.master),
      driver(driver_),
      rpdo_mapped(*this),
      tpdo_mapped(*this),
      tpdo_event_mutex(driver_.tpdo_event_mutex),
      num_(num),
      dev_(dev) {
  driver.Insert(*this);
}

BasicLogicalDriver::~BasicLogicalDriver() { driver.Erase(*this); }

SdoFuture<void>
BasicLogicalDriver::AsyncConfig() {
  SdoFuture<void> f;
  // A convenience function which reads and copies the device type from object
  // 67FF:00 (adjusted for logical device number) in the remote object
  // dictionary.
  auto read_67ff = [this]() {
    return AsyncRead<uint32_t>(0x67ff, 0).then(
        GetExecutor(),
        [this](SdoFuture<uint32_t> f) { dev_ = f.get().value(); });
  };
  if (num_ == 1) {
    // A convenience function which checks and copies the value of the
    // (expected) device type or, if it indicates multiple logical devices,
    // reads the value from object 67FF:00 in the remote object dictionary.
    auto check_1000 = [this, read_67ff](uint32_t value) -> SdoFuture<void> {
      if ((value) >> 16 == 0xffff) return read_67ff();
      dev_ = value;
      return make_empty_sdo_future();
    };
    ::std::error_code ec;
    // Try to read the expected device type from the local object dictionary
    // (object 1F84:$NODEID).
    auto value = driver.master[0x1f84][driver.id()].Read<uint32_t>(ec);
    if (!ec) {
      f = check_1000(value);
    } else {
      // If the expected device type is not available, read the device type from
      // the remote object dictionary (object 1000:00).
      f = AsyncRead<uint32_t>(0x1000, 0).then(
          GetExecutor(), [this, check_1000](SdoFuture<uint32_t> f) {
            return check_1000(f.get().value());
          });
    }
  } else {
    // This is not the first logical device. Read and copy the device type from
    // object 67FF:00 (adjusted for logical device number) in the remote object
    // dictionary.
    f = read_67ff();
  }
  // Run OnConfig() after the device type has been obtained.
  return f.then(GetExecutor(), [this](SdoFuture<void> f) {
    // Throw an exception if an SDO error occurred.
    f.get().value();
    // Only invoke OnConfig() if the previous operations succeeded.
    SdoPromise<void> p;
    OnConfig([p](::std::error_code ec) mutable {
      p.set(::std::make_exception_ptr(::std::system_error(ec, "OnConfig")));
    });
    return p.get_future();
  });
}

SdoFuture<void>
BasicLogicalDriver::AsyncDeconfig() {
  SdoPromise<void> p;
  // Post a task for OnDeconfig() to ensure this function does not block.
  GetExecutor().post([this, p]() mutable {
    OnDeconfig([p](::std::error_code ec) mutable {
      p.set(::std::make_exception_ptr(::std::system_error(ec, "OnDeconfig")));
    });
  });
  return p.get_future();
}

}  // namespace canopen

}  // namespace lely

#endif  // !LELY_NO_COAPP_MASTER
