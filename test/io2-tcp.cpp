#include "test.h"
#include <lely/ev/loop.hpp>
#if _WIN32
#include <lely/io2/win32/poll.hpp>
#elif _POSIX_C_SOURCE >= 200112L
#include <lely/io2/posix/poll.hpp>
#endif
#include <lely/io2/sys/io.hpp>
#include <lely/io2/sys/tcp.hpp>
#include <lely/io2/co_sock_stream.hpp>
#include <lely/io2/co_sock_stream_srv.hpp>

using namespace lely::ev;
using namespace lely::io;

void test(io_poll_t* poll, Loop& loop);

int
main() {
  tap_plan(2 * 4);

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
  TcpServer srv(poll, loop.get_executor());
  srv.open_ipv6();
  srv.bind(Ipv6TcpEndpoint("[::]:12345"), true);
  srv.listen(1);

  Tcp sock(poll, loop.get_executor());
  ::std::array<int, 4> rmsg;
  srv.submit_accept(sock, [&](::std::error_code) {
    tap_pass("accepted");
    sock.submit_read(buffer(rmsg), [](ssize_t result, ::std::error_code) {
      tap_pass("received");
      tap_diag("%d bytes read", (int)result);
    });
  });

  Tcp clt(poll, loop.get_executor());
  clt.open_ipv4();
  Ipv4TcpEndpoint endp("127.0.0.1:12345");
  ::std::array<int, 4> smsg{1, 2, 3, 4};
  clt.submit_connect(endp, [&](::std::error_code) {
    tap_pass("connected");
    clt.submit_write(const_buffer(smsg), [](ssize_t result, ::std::error_code) {
      tap_pass("sent");
      tap_diag("%d bytes written", (int)result);
    });
  });

  loop.restart();
  loop.run();
}
