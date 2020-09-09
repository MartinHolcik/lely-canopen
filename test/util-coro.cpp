#include "test.h"
#include <lely/util/coro.hpp>
#include <lely/util/coro_sched.hpp>

#if !LELY_NO_THREADS && !__MINGW32__
#include <thread>
#include <vector>
#endif

using namespace lely::util;

#define NUM_THRD 9
#define NUM_CORO 1000
#define NUM_YIELD 100

int
main() {
  tap_plan(4);

  CoroutineThread thrd;

  CoroutineTimedMutex timed_mtx;
  CoroutineMutex mtx;
  CoroutineConditionVariable cond;

  Coroutine c1([&]() {
    {
      tap_diag("1: before lock");
      ::std::unique_lock<CoroutineTimedMutex> lock(timed_mtx);
      tap_diag("1: after lock, before sleep");
      this_coro::sleep_for(::std::chrono::seconds(1));
      tap_diag("1: after yield, before unlock");
    }
    tap_diag("1: after unlock, before yield");
    this_coro::yield();
    tap_diag("1: after yield, before lock");
    {
      ::std::unique_lock<CoroutineMutex> lock(mtx);
      tap_diag("1: after lock, before wait");
      cond.wait(lock);
      tap_diag("1: after wait, before unlock");
    }
    tap_diag("1: after unlock, before lock");
    {
      ::std::unique_lock<CoroutineMutex> lock(mtx);
      tap_diag("1: after lock, before wait");
      tap_test(cond.wait_for(lock, ::std::chrono::seconds(1)) ==
               cv_status::timeout);
      tap_diag("1: after wait, before unlock");
    }
    tap_diag("1: after unlock, before exit");
  });

  Coroutine c2([&]() {
    {
      tap_diag("2: before try_lock");
      ::std::unique_lock<CoroutineTimedMutex> lock(timed_mtx,
                                                   ::std::try_to_lock);
      tap_test(!lock);
      tap_diag("2: before try_lock_for(0.5s)");
      tap_test(!lock.try_lock_for(::std::chrono::milliseconds(500)));
      tap_diag("2: before try_lock_for(1s)");
      tap_test(lock.try_lock_for(::std::chrono::seconds(1)));
      tap_diag("2: after try_lock_for, before unlock");
    }
    tap_diag("2: after unlock, before yield");
    this_coro::yield();
    tap_diag("2: after yield, before lock");
    {
      ::std::unique_lock<CoroutineMutex> lock(mtx);  // optional
      tap_diag("2: after lock, before notify");
      cond.notify_one();
      tap_diag("2: after notify, before unlock");
    }
    tap_diag("2: after unlock, before exit");
  });

  c1.join();
  c2.join();

#if !LELY_NO_THREADS && !__MINGW32__
  ::std::size_t n = NUM_THRD * NUM_CORO;

  ::std::vector<::std::thread> threads(NUM_THRD);
  for (int i = 0; i < NUM_THRD; i++) {
    threads[i] = ::std::thread(
        [&](int id) {
          coro_sched_ctor_t* ctor = nullptr;
          switch (id % 3) {
            case 0:
              ctor = coro_sched_rr_ctor();
              break;
            case 1:
              ctor = coro_sched_sw_ctor();
              break;
            case 2:
              ctor = coro_sched_ws_ctor(NUM_THRD / 3);
              break;
          }
          CoroutineThread thrd(CORO_ATTR_INIT, ctor);

          ::std::vector<Coroutine> coros(NUM_CORO);
          for (auto& coro : coros) {
            coro = Coroutine([&]() {
              for (int i = 0; i < NUM_YIELD; i++) {
                ::std::unique_lock<CoroutineTimedMutex> lock(
                    timed_mtx, ::std::try_to_lock);
                if (!lock) lock.try_lock_for(::std::chrono::milliseconds(1));
                this_coro::yield();
              }
              ::std::lock_guard<CoroutineTimedMutex> lock(timed_mtx);
              n--;
            });
          }

          for (int i = 0; i < NUM_YIELD; i++) {
            ::std::unique_lock<CoroutineTimedMutex> lock(timed_mtx,
                                                         ::std::try_to_lock);
            if (!lock) lock.try_lock_for(::std::chrono::milliseconds(1));
            this_coro::yield();
          }

          for (;;) {
            {
              ::std::lock_guard<CoroutineTimedMutex> lock(timed_mtx);
              if (!n) break;
            }
            this_coro::yield();
          }
        },
        i);
  }

  for (auto& thr : threads) thr.join();
#endif  // !LELY_NO_THREADS && !__MINGW32__

  return 0;
}
