#include "test.h"
#include <lely/ev/loop.hpp>
#if _WIN32
#include <lely/io2/win32/poll.hpp>
#elif _POSIX_C_SOURCE >= 200112L
#include <lely/io2/posix/poll.hpp>
#endif
#include <lely/io2/sys/io.hpp>
#include <lely/io2/sys/udp.hpp>
#include <lely/io2/co_sock_dgram.hpp>

using namespace lely::ev;
using namespace lely::io;

void test(io_poll_t* poll, Loop& loop);

int
main() {
  tap_plan(2 * 2);

  IoGuard io_guard;
  Context ctx;
  lely::io::Poll poll(ctx);
  Loop loop(poll.get_poll());

  test(nullptr, loop);
  test(poll, loop);

  return 0;
}

void
test(io_poll_t* poll, Loop& loop) {
  Udp srv(poll, loop.get_executor());
  srv.open_ipv6();
  srv.bind(Ipv6UdpEndpoint("[::]:12345"), true);

  Udp clt(poll, loop.get_executor());
  clt.open_ipv4();

  MessageFlag flags = MessageFlag::NONE;

  ::std::array<int, 4> rmsg;
  Ipv6UdpEndpoint rendp;
  srv.submit_receive(buffer(rmsg), flags, rendp,
                     [&](ssize_t result, MessageFlag, ::std::error_code) {
                       tap_pass("received");
                       tap_diag("%d bytes read from from %s", (int)result,
                                rendp.to_string().c_str());
                     });

  ::std::array<int, 4> smsg{1, 2, 3, 4};
  Ipv4UdpEndpoint sendp("127.0.0.1:12345");
  clt.submit_send(const_buffer(smsg), flags, sendp,
                  [](ssize_t result, ::std::error_code) {
                    tap_pass("sent");
                    tap_diag("%d bytes written", (int)result);
                  });

  loop.restart();
  loop.run();
}
