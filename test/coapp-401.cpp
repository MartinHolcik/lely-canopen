#include "test.h"
#include <lely/coapp/drivers/401.hpp>
#include <lely/coapp/fiber_driver.hpp>
#include <lely/coapp/slave.hpp>
#include <lely/ev/loop.hpp>
#if _WIN32
#include <lely/io2/win32/poll.hpp>
#elif _POSIX_C_SOURCE >= 200112L
#include <lely/io2/posix/poll.hpp>
#else
#error This file requires Windows or POSIX.
#endif
#include <lely/io2/sys/clock.hpp>
#include <lely/io2/sys/io.hpp>
#include <lely/io2/sys/timer.hpp>
#include <lely/io2/vcan.hpp>

using namespace lely::ev;
using namespace lely::io;
using namespace lely::canopen;

#define NUM_SYNC 8

class Slave401 : public BasicSlave {
 public:
  using BasicSlave::BasicSlave;

 private:
  void
  OnSync(uint8_t, const time_point&) noexcept override {
    {
      uint8_t value = (*this)[0x6000][1];
      (*this)[0x6000][1] = ++value;
    }

    {
      int16_t value = (*this)[0x6C01][1];
      (*this)[0x6C01][1] = ++value;
    }
  }
};

class Driver401 : public FiberDriver {
  class Logical401 : public Basic401Driver {
   public:
    Logical401(Driver401& driver_, int num)
        : Basic401Driver(driver_, num), driver(driver_) {}

    Driver401& driver;

   private:
    void
    OnDigitalInput(int i, bool value) noexcept override {
      driver.OnDigitalInput(Number(), i, value);
    }

    void
    OnAnalogInput16(int i, int16_t value) noexcept override {
      driver.OnAnalogInput(Number(), i, value);
    }
  };

 public:
  Driver401(ev_exec_t* exec, BasicMaster& master, uint8_t id)
      : FiberDriver(exec, master, id), ldev1_(*this, 1), ldev2_(*this, 2) {}

 private:
  void
  OnSync(uint8_t, const time_point&) noexcept override {
    tap_diag("master: sent SYNC");

    // Initiate a clean shutdown.
    if (++n_ >= NUM_SYNC)
      master.AsyncDeconfig(id()).submit(
          GetExecutor(), [&]() { master.GetContext().shutdown(); });
  }

  void
  OnBoot(NmtState, char es, const ::std::string&) noexcept override {
    tap_test(!es, "master: slave #%d successfully booted", id());

    tap_test(ldev1_.HasDigitalInputs(), "logical device 1 has digital inputs");
    tap_test(ldev1_.HasDigitalOutputs(),
             "logical device 1 has digital outputs");

    tap_test(ldev2_.HasAnalogInputs(), "logical device 2 has analog inputs");
    tap_test(ldev2_.HasAnalogOutputs(), "logical device 2 has analog outputs");

    // Start SYNC production.
    master[0x1006][0] = UINT32_C(1000000);
  }

  void
  OnDigitalInput(int /*num*/, int i, bool value) noexcept {
    tap_diag("master: digital input %d is now %d", i, value);
  }

  void
  OnAnalogInput(int /*num*/, int i, int16_t value) noexcept {
    tap_diag("master: analog input %d is now %d", i, value);
  }

  Logical401 ldev1_;
  Logical401 ldev2_;

  int n_{0};
};

int
main() {
  tap_plan(2 + 5);

  IoGuard io_guard;
  Context ctx;
  lely::io::Poll poll(ctx);
  Loop loop(poll.get_poll());
  auto exec = loop.get_executor();
  Timer timer(poll, exec, CLOCK_MONOTONIC);
  VirtualCanController ctrl(clock_monotonic);

  VirtualCanChannel schan(ctx, exec);
  schan.open(ctrl);
  tap_test(schan.is_open(), "slave: opened virtual CAN channel");
  Slave401 slave(timer, schan, TEST_SRCDIR "/coapp-401-slave.dcf", "", 127);

  VirtualCanChannel mchan(ctx, exec);
  mchan.open(ctrl);
  tap_test(mchan.is_open(), "master: opened virtual CAN channel");
  AsyncMaster master(timer, mchan, TEST_SRCDIR "/coapp-401-master.dcf", "", 1);
  Driver401 driver(exec, master, 127);

  slave.Reset();
  master.Reset();

  loop.run();

  return 0;
}
