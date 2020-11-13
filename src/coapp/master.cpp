/**@file
 * This file is part of the C++ CANopen application library; it contains the
 * implementation of the CANopen master.
 *
 * @see lely/coapp/master.hpp
 *
 * @copyright 2018-2020 Lely Industries N.V.
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

#include <lely/co/dev.h>
#include <lely/co/nmt.h>
#include <lely/co/obj.h>
#include <lely/coapp/driver.hpp>

#include <algorithm>
#include <array>
#include <map>
#include <string>

#include <cassert>

namespace lely {

namespace canopen {

/// The internal implementation of the CANopen master.
struct BasicMaster::Impl_ {
  Impl_(BasicMaster* self, co_nmt_t* nmt);

  ev::Future<void> AsyncDeconfig(DriverBase* driver);

  void OnNgInd(co_nmt_t* nmt, uint8_t id, int state, int reason) noexcept;
  void OnBootInd(co_nmt_t* nmt, uint8_t id, uint8_t st, char es) noexcept;
  void OnCfgInd(co_nmt_t* nmt, uint8_t id, co_csdo_t* sdo) noexcept;

  BasicMaster* self;
  ::std::function<void(uint8_t, bool)> on_node_guarding;
  ::std::function<void(uint8_t, NmtState, char, const ::std::string&)> on_boot;
  ::std::array<bool, CO_NUM_NODES> ready{{false}};
  ::std::array<bool, CO_NUM_NODES> config{{false}};
  ::std::map<uint8_t, Sdo> sdos;
};

BasicMaster::SubObjectIterator::SubObjectIterator(BasicMaster* master,
                                                  void* obj) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0, 0),
      obj_(obj) {
  assert(master);
}

BasicMaster::SubObjectIterator::SubObjectIterator(BasicMaster* master,
                                                  void* obj, void* sub) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0,
           sub ? co_sub_get_subidx(static_cast<co_sub_t*>(sub)) : 0),
      obj_(obj),
      sub_(sub) {
  assert(master);
}

BasicMaster::SubObjectIterator&
BasicMaster::SubObjectIterator::operator++() noexcept {
  sub_ = sub_ ? co_sub_next(static_cast<co_sub_t*>(sub_))
              : obj_ ? co_obj_first_sub(static_cast<co_obj_t*>(obj_)) : nullptr;
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  val_.subidx_ = sub_ ? co_sub_get_subidx(static_cast<co_sub_t*>(sub_)) : 0;
  return *this;
}

BasicMaster::SubObjectIterator&
BasicMaster::SubObjectIterator::operator--() noexcept {
  sub_ = sub_ ? co_sub_prev(static_cast<co_sub_t*>(sub_))
              : obj_ ? co_obj_last_sub(static_cast<co_obj_t*>(obj_)) : nullptr;
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  val_.subidx_ = sub_ ? co_sub_get_subidx(static_cast<co_sub_t*>(sub_)) : 0;
  return *this;
}

BasicMaster::ConstSubObjectIterator::ConstSubObjectIterator(
    const BasicMaster* master, void* obj) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0, 0),
      obj_(obj) {
  assert(master);
}

BasicMaster::ConstSubObjectIterator::ConstSubObjectIterator(
    const BasicMaster* master, void* obj, void* sub) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0,
           sub ? co_sub_get_subidx(static_cast<co_sub_t*>(sub)) : 0),
      obj_(obj),
      sub_(sub) {
  assert(master);
}

BasicMaster::ConstSubObjectIterator&
BasicMaster::ConstSubObjectIterator::operator++() noexcept {
  sub_ = sub_ ? co_sub_next(static_cast<co_sub_t*>(sub_))
              : obj_ ? co_obj_first_sub(static_cast<co_obj_t*>(obj_)) : nullptr;
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  val_.subidx_ = sub_ ? co_sub_get_subidx(static_cast<co_sub_t*>(sub_)) : 0;
  return *this;
}

BasicMaster::ConstSubObjectIterator&
BasicMaster::ConstSubObjectIterator::operator--() noexcept {
  sub_ = sub_ ? co_sub_prev(static_cast<co_sub_t*>(sub_))
              : obj_ ? co_obj_last_sub(static_cast<co_obj_t*>(obj_)) : nullptr;
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  val_.subidx_ = sub_ ? co_sub_get_subidx(static_cast<co_sub_t*>(sub_)) : 0;
  return *this;
}

BasicMaster::Object::iterator
BasicMaster::Object::begin() noexcept {
  return ++end();
}

BasicMaster::Object::const_iterator
BasicMaster::Object::cbegin() const noexcept {
  return ++cend();
}

BasicMaster::Object::iterator
BasicMaster::Object::end() noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx_)};
}

BasicMaster::Object::const_iterator
BasicMaster::Object::cend() const noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx_)};
}

BasicMaster::Object::iterator
BasicMaster::Object::find(uint8_t subidx) noexcept {
  assert(master_);
  auto obj = co_dev_find_obj(master_->dev(), idx_);
  auto sub = obj ? co_obj_find_sub(obj, subidx) : nullptr;
  return {master_, obj, sub};
}

BasicMaster::Object::const_iterator
BasicMaster::Object::find(uint8_t subidx) const noexcept {
  assert(master_);
  auto obj = co_dev_find_obj(master_->dev(), idx_);
  auto sub = obj ? co_obj_find_sub(obj, subidx) : nullptr;
  return {master_, obj, sub};
}

bool
BasicMaster::Object::contains(uint8_t subidx) const noexcept {
  assert(master_);
  return co_dev_find_sub(master_->dev(), idx_, subidx) != nullptr;
}

BasicMaster::ObjectIterator::ObjectIterator(BasicMaster* master) noexcept
    : val_(master, 0) {
  assert(master);
}

BasicMaster::ObjectIterator::ObjectIterator(BasicMaster* master,
                                            void* obj) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0),
      obj_(obj) {
  assert(master);
}

BasicMaster::ObjectIterator&
BasicMaster::ObjectIterator::operator++() noexcept {
  assert(val_.master_);
  obj_ = obj_ ? co_obj_next(static_cast<co_obj_t*>(obj_))
              : co_dev_first_obj(val_.master_->dev());
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  return *this;
}

BasicMaster::ObjectIterator&
BasicMaster::ObjectIterator::operator--() noexcept {
  assert(val_.master_);
  obj_ = obj_ ? co_obj_prev(static_cast<co_obj_t*>(obj_))
              : co_dev_last_obj(val_.master_->dev());
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  return *this;
}

BasicMaster::ConstObject::const_iterator
BasicMaster::ConstObject::cbegin() const noexcept {
  return ++cend();
}

BasicMaster::ConstObject::const_iterator
BasicMaster::ConstObject::cend() const noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx_)};
}

BasicMaster::ConstObject::const_iterator
BasicMaster::ConstObject::find(uint8_t subidx) const noexcept {
  assert(master_);
  auto obj = co_dev_find_obj(master_->dev(), idx_);
  auto sub = obj ? co_obj_find_sub(obj, subidx) : nullptr;
  return {master_, obj, sub};
}

bool
BasicMaster::ConstObject::contains(uint8_t subidx) const noexcept {
  assert(master_);
  return co_dev_find_sub(master_->dev(), idx_, subidx) != nullptr;
}

BasicMaster::ConstObjectIterator::ConstObjectIterator(
    const BasicMaster* master) noexcept
    : val_(master, 0) {
  assert(master);
}

BasicMaster::ConstObjectIterator::ConstObjectIterator(const BasicMaster* master,
                                                      void* obj) noexcept
    : val_(master, obj ? co_obj_get_idx(static_cast<co_obj_t*>(obj)) : 0),
      obj_(obj) {
  assert(master);
}

BasicMaster::ConstObjectIterator&
BasicMaster::ConstObjectIterator::operator++() noexcept {
  assert(val_.master_);
  obj_ = obj_ ? co_obj_next(static_cast<co_obj_t*>(obj_))
              : co_dev_first_obj(val_.master_->dev());
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  return *this;
}

BasicMaster::ConstObjectIterator&
BasicMaster::ConstObjectIterator::operator--() noexcept {
  assert(val_.master_);
  obj_ = obj_ ? co_obj_prev(static_cast<co_obj_t*>(obj_))
              : co_dev_last_obj(val_.master_->dev());
  val_.idx_ = obj_ ? co_obj_get_idx(static_cast<co_obj_t*>(obj_)) : 0;
  return *this;
}

BasicMaster::Local::iterator
BasicMaster::Local::begin() noexcept {
  return ++end();
}

BasicMaster::Local::const_iterator
BasicMaster::Local::cbegin() const noexcept {
  return ++cend();
}

BasicMaster::Local::iterator
BasicMaster::Local::end() noexcept {
  return {master_};
}

BasicMaster::Local::const_iterator
BasicMaster::Local::cend() const noexcept {
  return {master_};
}

BasicMaster::Local::iterator
BasicMaster::Local::find(uint16_t idx) noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx)};
}

BasicMaster::Local::const_iterator
BasicMaster::Local::find(uint16_t idx) const noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx)};
}

bool
BasicMaster::Local::contains(uint16_t idx) const noexcept {
  assert(master_);
  return co_dev_find_obj(master_->dev(), idx) != nullptr;
}

BasicMaster::ConstLocal::const_iterator
BasicMaster::ConstLocal::cbegin() const noexcept {
  return ++cend();
}

BasicMaster::ConstLocal::const_iterator
BasicMaster::ConstLocal::cend() const noexcept {
  return {master_};
}

BasicMaster::ConstLocal::const_iterator
BasicMaster::ConstLocal::find(uint16_t idx) const noexcept {
  assert(master_);
  return {master_, co_dev_find_obj(master_->dev(), idx)};
}

bool
BasicMaster::ConstLocal::contains(uint16_t idx) const noexcept {
  assert(master_);
  return co_dev_find_obj(master_->dev(), idx) != nullptr;
}

void
BasicMaster::TpdoEventMutex::lock() {
  ::std::lock_guard<util::BasicLockable> lock(*node);
  Node::TpdoEventMutex::lock();
}

void
BasicMaster::TpdoEventMutex::unlock() {
  ::std::lock_guard<util::BasicLockable> lock(*node);
  Node::TpdoEventMutex::unlock();
}

BasicMaster::BasicMaster(ev_exec_t* exec, io::TimerBase& timer,
                         io::CanChannelBase& chan, const ::std::string& dcf_txt,
                         const ::std::string& dcf_bin, uint8_t id)
    : Node(exec, timer, chan, dcf_txt, dcf_bin, id),
      local(this),
      const_local(this),
      tpdo_event_mutex(*this),
      impl_(new Impl_(this, Node::nmt())) {}

BasicMaster::~BasicMaster() = default;

bool
BasicMaster::Boot(uint8_t id) {
  if (!id || id > CO_NUM_NODES) return false;

  ::std::lock_guard<util::BasicLockable> lock(*this);

  if (co_nmt_is_booting(nmt(), id)) return false;

  // Abort any ongoing or pending SDO requests for the slave, since the master
  // MAY need the Client-SDO service for the NMT 'boot slave' process.
  CancelSdo(id);

  auto ready = impl_->ready[id - 1];
  impl_->ready[id - 1] = false;
  if (co_nmt_boot_req(nmt(), id, co_nmt_get_timeout(nmt())) == -1) {
    impl_->ready[id - 1] = ready;
    util::throw_errc("Boot");
  }

  return true;
}

bool
BasicMaster::IsReady(uint8_t id) const {
  if (!id || id > CO_NUM_NODES) return false;

  ::std::lock_guard<util::BasicLockable> lock(const_cast<BasicMaster&>(*this));
  return impl_->ready[id - 1];
}

ev::Future<void>
BasicMaster::AsyncDeconfig(uint8_t id) {
  {
    ::std::lock_guard<util::BasicLockable> lock(*this);
    auto it = find(id);
    if (it != end()) return impl_->AsyncDeconfig(it->second);
  }
  return ev::make_empty_future();
}

ev::Future<::std::size_t, void>
BasicMaster::AsyncDeconfig() {
  ::std::array<ev::Future<void>, CO_NUM_NODES> futures;
  ::std::size_t n = 0;
  {
    ::std::lock_guard<util::BasicLockable> lock(*this);
    for (const auto& it : *this) futures[n++] = impl_->AsyncDeconfig(it.second);
  }
  // Create a temporary array of pointers, since ev::Future is not guaranteed to
  // be the same size as ev_future_t*.
  ::std::array<ev_future_t*, CO_NUM_NODES> tmp;
  ::std::copy_n(futures.begin(), n, tmp.begin());
  return ev::when_all(GetExecutor(), n, tmp.data());
}

void
BasicMaster::Error(uint8_t id) {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  if (co_nmt_node_err_ind(nmt(), id) == -1) util::throw_errc("Error");
}

void
BasicMaster::Error(uint16_t eec, uint8_t er, const uint8_t msef[5]) noexcept {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  Node::Error(eec, er, msef);
}

void
BasicMaster::Command(NmtCommand cs, uint8_t id) {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  if (co_nmt_cs_req(nmt(), static_cast<uint8_t>(cs), id) == -1)
    util::throw_errc("Command");
}

void
BasicMaster::RpdoRtr(int num) noexcept {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  Node::RpdoRtr(num);
}

void
BasicMaster::TpdoEvent(int num) noexcept {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  Node::TpdoEvent(num);
}

::std::chrono::milliseconds
BasicMaster::GetTimeout() const {
  ::std::lock_guard<util::BasicLockable> lock(const_cast<BasicMaster&>(*this));

  return detail::from_sdo_timeout(co_nmt_get_timeout(nmt()));
}

void
BasicMaster::SetTimeout(const ::std::chrono::milliseconds& timeout) {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  co_nmt_set_timeout(nmt(), detail::to_sdo_timeout(timeout));
}

void
BasicMaster::Insert(DriverBase& driver) {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  if (!driver.id() || driver.id() > 0x7f)
    throw ::std::out_of_range("invalid node-ID: " +
                              ::std::to_string(driver.id()));
  if (driver.id() == co_dev_get_id(co_nmt_get_dev(nmt())))
    throw ::std::out_of_range("cannot register node-ID of master: " +
                              ::std::to_string(driver.id()));
  if (find(driver.id()) != end())
    throw ::std::out_of_range("node-ID " + ::std::to_string(driver.id()) +
                              " already registered");

  MapType::operator[](driver.id()) = &driver;
}

void
BasicMaster::Erase(DriverBase& driver) {
  ::std::lock_guard<util::BasicLockable> lock(*this);

  auto id = driver.id();
  auto it = find(id);
  if (it != end() && it->second == &driver) {
    CancelSdo(id);
    erase(it);
  }
}

void
BasicMaster::OnNodeGuarding(
    ::std::function<void(uint8_t, bool)> on_node_guarding) {
  ::std::lock_guard<util::BasicLockable> lock(*this);
  impl_->on_node_guarding = on_node_guarding;
}

void
BasicMaster::OnBoot(
    ::std::function<void(uint8_t, NmtState, char, const ::std::string&)>
        on_boot) {
  ::std::lock_guard<util::BasicLockable> lock(*this);
  impl_->on_boot = on_boot;
}

void
BasicMaster::IsReady(uint8_t id, bool ready) noexcept {
  if (id && id <= CO_NUM_NODES) impl_->ready[id - 1] = ready;
}

void
BasicMaster::OnCanError(io::CanError error) noexcept {
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnCanError(error);
  }
}

void
BasicMaster::OnCanState(io::CanState new_state,
                        io::CanState old_state) noexcept {
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnCanState(new_state, old_state);
  }
}

void
BasicMaster::OnRpdoWrite(uint8_t id, uint16_t idx, uint8_t subidx) noexcept {
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnRpdoWrite(idx, subidx);
  }
}

void
BasicMaster::OnCommand(NmtCommand cs) noexcept {
  // Abort all ongoing and pending SDO requests unless the master is in the
  // pre-operational or operational state.
  if (cs != NmtCommand::ENTER_PREOP && cs != NmtCommand::START) CancelSdo();
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnCommand(cs);
  }
}

void
BasicMaster::OnNodeGuarding(uint8_t id, bool occurred) noexcept {
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnNodeGuarding(occurred);
  }
}

void
BasicMaster::OnHeartbeat(uint8_t id, bool occurred) noexcept {
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnHeartbeat(occurred);
  }
}

void
BasicMaster::OnState(uint8_t id, NmtState st) noexcept {
  if (st == NmtState::BOOTUP && !IsConfig(id)) {
    IsReady(id, false);
    // Abort any ongoing or pending SDO requests for the slave, since the master
    // MAY need the Client-SDO service for the NMT 'boot slave' process.
    CancelSdo(id);
  }
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnState(st);
  }
}

void
BasicMaster::OnBoot(uint8_t id, NmtState st, char es,
                    const ::std::string& what) noexcept {
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnBoot(st, es, what);
  }
}

void
BasicMaster::OnConfig(uint8_t id) noexcept {
  auto it = find(id);
  // If no remote interface is registered for this node, the 'update
  // configuration' process is considered complete.
  if (it == end()) {
    ConfigResult(id, ::std::error_code());
    return;
  }
  // Let the driver perform the configuration update.
  util::UnlockGuard<util::BasicLockable> unlock(*this);
  it->second->OnConfig([this, id](::std::error_code ec) {
    ::std::lock_guard<util::BasicLockable> lock(*this);
    // Report the result of the 'update configuration' process.
    ConfigResult(id, ec);
  });
}

void
BasicMaster::ConfigResult(uint8_t id, ::std::error_code ec) noexcept {
  assert(id && id <= CO_NUM_NODES);
  impl_->config[id - 1] = false;
  if (co_nmt_is_booting(nmt(), id))
    // Destroy the Client-SDO, since it will be taken over by the master.
    impl_->sdos.erase(id);
  // Ignore any errors, since we cannot handle them here.
  co_nmt_cfg_res(nmt(), id, static_cast<uint32_t>(sdo_errc(ec)));
}

void
BasicMaster::OnSync(uint8_t cnt, const time_point& t) noexcept {
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnSync(cnt, t);
  }
}

void
BasicMaster::OnSyncError(uint16_t eec, uint8_t er) noexcept {
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnSyncError(eec, er);
  }
}

void
BasicMaster::OnTime(
    const ::std::chrono::system_clock::time_point& abs_time) noexcept {
  for (const auto& it : *this) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it.second->OnTime(abs_time);
  }
}

void
BasicMaster::OnEmcy(uint8_t id, uint16_t eec, uint8_t er,
                    uint8_t msef[5]) noexcept {
  auto it = find(id);
  if (it != end()) {
    util::UnlockGuard<util::BasicLockable> unlock(*this);
    it->second->OnEmcy(eec, er, msef);
  }
}

bool
BasicMaster::IsConfig(uint8_t id) const {
  if (!id || id > CO_NUM_NODES) return false;

  return impl_->config[id - 1];
}

Sdo*
BasicMaster::GetSdo(uint8_t id) {
  if (!id || id > 0x7f)
    throw ::std::out_of_range("invalid node-ID: " + ::std::to_string(id));
  // The Client-SDO service only exists in the pre-operational and operational
  // state.
  auto st = co_nmt_get_st(nmt());
  if (st != CO_NMT_ST_PREOP && st != CO_NMT_ST_START) return nullptr;
  // During the 'update configuration' step of the NMT 'boot slave' process, a
  // Client-SDO queue may be available.
  auto it = impl_->sdos.find(id);
  if (it != impl_->sdos.end()) return &it->second;
  // The master needs the Client-SDO service during the NMT 'boot slave'
  // process.
  if (co_nmt_is_booting(nmt(), id)) return nullptr;
  // Return a Client-SDO queue for the default SDO.
  return &(impl_->sdos[id] = Sdo(co_nmt_get_net(nmt()), id));
}

void
BasicMaster::CancelSdo(uint8_t id) {
  if (id)
    impl_->sdos.erase(id);
  else
    impl_->sdos.clear();
}

void
AsyncMaster::OnCanError(io::CanError error) noexcept {
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post([=]() { driver->OnCanError(error); });
  }
}

void
AsyncMaster::OnCanState(io::CanState new_state,
                        io::CanState old_state) noexcept {
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post(
        [=]() { driver->OnCanState(new_state, old_state); });
  }
}

void
AsyncMaster::OnRpdoWrite(uint8_t id, uint16_t idx, uint8_t subidx) noexcept {
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post([=]() { driver->OnRpdoWrite(idx, subidx); });
  }
}

void
AsyncMaster::OnCommand(NmtCommand cs) noexcept {
  // Abort all ongoing and pending SDO requests unless the master is in the
  // pre-operational or operational state.
  if (cs != NmtCommand::ENTER_PREOP && cs != NmtCommand::START) CancelSdo();
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post([=]() { driver->OnCommand(cs); });
  }
}

void
AsyncMaster::OnNodeGuarding(uint8_t id, bool occurred) noexcept {
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post([=]() { driver->OnNodeGuarding(occurred); });
  }
}

void
AsyncMaster::OnHeartbeat(uint8_t id, bool occurred) noexcept {
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post([=]() { driver->OnHeartbeat(occurred); });
  }
}

void
AsyncMaster::OnState(uint8_t id, NmtState st) noexcept {
  if (st == NmtState::BOOTUP && !IsConfig(id)) {
    IsReady(id, false);
    // Abort any ongoing or pending SDO requests for the slave, since the master
    // MAY need the Client-SDO service for the NMT 'boot slave' process.
    CancelSdo(id);
  }
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post([=]() { driver->OnState(st); });
  }
}

void
AsyncMaster::OnBoot(uint8_t id, NmtState st, char es,
                    const ::std::string& what) noexcept {
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post([=]() { driver->OnBoot(st, es, what); });
  }
}

void
AsyncMaster::OnConfig(uint8_t id) noexcept {
  auto it = find(id);
  // If no remote interface is registered for this node, the 'update
  // configuration' process is considered complete.
  if (it == end()) {
    ConfigResult(id, ::std::error_code());
    return;
  }

  // Let the driver perform the configuration update.
  DriverBase* driver = it->second;
  driver->GetExecutor().post([this, id, driver]() {
    driver->OnConfig([this, id](::std::error_code ec) {
      ::std::lock_guard<util::BasicLockable> lock(*this);
      ConfigResult(id, ec);
    });
  });
}

void
AsyncMaster::OnSync(uint8_t cnt, const time_point& t) noexcept {
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post([=]() { driver->OnSync(cnt, t); });
  }
}

void
AsyncMaster::OnSyncError(uint16_t eec, uint8_t er) noexcept {
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post([=]() { driver->OnSyncError(eec, er); });
  }
}

void
AsyncMaster::OnTime(
    const ::std::chrono::system_clock::time_point& abs_time) noexcept {
  for (const auto& it : *this) {
    DriverBase* driver = it.second;
    driver->GetExecutor().post([=]() { driver->OnTime(abs_time); });
  }
}

void
AsyncMaster::OnEmcy(uint8_t id, uint16_t eec, uint8_t er,
                    uint8_t msef[5]) noexcept {
  ::std::array<uint8_t, 5> value = {0};
  ::std::copy_n(msef, value.size(), value.begin());
  auto it = find(id);
  if (it != end()) {
    DriverBase* driver = it->second;
    driver->GetExecutor().post(
        [=]() mutable { driver->OnEmcy(eec, er, value.data()); });
  }
}

BasicMaster::Impl_::Impl_(BasicMaster* self_, co_nmt_t* nmt) : self(self_) {
  co_nmt_set_ng_ind(
      nmt,
      [](co_nmt_t* nmt, uint8_t id, int state, int reason,
         void* data) noexcept {
        static_cast<Impl_*>(data)->OnNgInd(nmt, id, state, reason);
      },
      this);

  co_nmt_set_boot_ind(
      nmt,
      [](co_nmt_t* nmt, uint8_t id, uint8_t st, char es, void* data) noexcept {
        static_cast<Impl_*>(data)->OnBootInd(nmt, id, st, es);
      },
      this);

  co_nmt_set_cfg_ind(
      nmt,
      [](co_nmt_t* nmt, uint8_t id, co_csdo_t* sdo, void* data) noexcept {
        static_cast<Impl_*>(data)->OnCfgInd(nmt, id, sdo);
      },
      this);
}

ev::Future<void>
BasicMaster::Impl_::AsyncDeconfig(DriverBase* driver) {
  self->IsReady(driver->id(), false);
  ev::Promise<void> p;
  driver->GetExecutor().post([=]() mutable {
    driver->OnDeconfig([p](::std::error_code ec) mutable { p.set(ec); });
  });
  return p.get_future();
}

void
BasicMaster::Impl_::OnNgInd(co_nmt_t* nmt, uint8_t id, int state,
                            int reason) noexcept {
  // Invoke the default behavior before notifying the implementation.
  co_nmt_on_ng(nmt, id, state, reason);
  // Only handle node guarding timeout events. State changes are handled by
  // OnSt().
  if (reason != CO_NMT_EC_TIMEOUT) return;
  // Notify the implementation.
  bool occurred = state == CO_NMT_EC_OCCURRED;
  self->OnNodeGuarding(id, occurred);
  if (on_node_guarding) {
    auto f = on_node_guarding;
    util::UnlockGuard<util::BasicLockable> unlock(*self);
    f(id, occurred);
  }
}

void
BasicMaster::Impl_::OnBootInd(co_nmt_t*, uint8_t id, uint8_t st,
                              char es) noexcept {
  if (id && id <= CO_NUM_NODES && (!es || es == 'L')) ready[id - 1] = true;
  ::std::string what = es ? co_nmt_es2str(es) : "";
  self->OnBoot(id, static_cast<NmtState>(st), es, what);
  if (on_boot) {
    auto f = on_boot;
    util::UnlockGuard<util::BasicLockable> unlock(*self);
    f(id, static_cast<NmtState>(st), es, what);
  }
}

void
BasicMaster::Impl_::OnCfgInd(co_nmt_t*, uint8_t id, co_csdo_t* sdo) noexcept {
  // Create a Client-SDO for the 'update configuration' process.
  try {
    sdos[id] = Sdo(sdo);
  } catch (...) {
    self->ConfigResult(id, SdoErrc::ERROR);
    return;
  }
  config[id - 1] = true;
  self->OnConfig(id);
}

}  // namespace canopen

}  // namespace lely

#endif  // !LELY_NO_COAPP_MASTER
