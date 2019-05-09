/**@file
 * This is the internal header file of the common file descriptor functions.
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

#ifndef LELY_IO2_INTERN_POSIX_FD_H_
#define LELY_IO2_INTERN_POSIX_FD_H_

#include "io.h"

#if _POSIX_C_SOURCE >= 200112L

#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sets the `FD_CLOEXEC` flag of the file descriptor <b>fd</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained from `errno`.
 */
int io_fd_set_cloexec(int fd);

/**
 * Sets the `O_NONBLOCK` flag of the file descriptor <b>fd</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained from `errno`.
 */
int io_fd_set_nonblock(int fd);

/**
 * Waits for one or more of the I/O events in *<b>events</b> to occur as if by
 * POSIX `poll()`. On succes, the reported events are stored in *<b>events</b>.
 *
 * @returns 0 on success, or -1 on error. In the latter case, the error number
 * can be obtained from `errno`.
 */
int io_fd_wait(int fd, int *events, int timeout);

/**
 * Equivalent to `socket(domain, type, protocol)`, except that the resulting
 * socket has the `O_CLOEXEC` and `O_NONBLOCK` flags set.
 */
int io_fd_socket(int domain, int type, int protocol);

/**
 * Equivalent to POSIX `accept(fd, addr, addrlen)`, except that if <b>fd</b> is
 * non-blocking and <b>timeout</b> is non-negative, this function will block
 * until a pending connection is accepted or <b>timeout</b> milliseconds have
 * elapsed. The timeout interval will be rounded up to the system clock
 * granularity, but this function MAY return early if interrupted by a signal.
 * If `O_CLOEXEC` or `O_NONBLOCK` are set in <b>flags</b>, these flags will be
 * set on the file descriptor for the accepted socket.
 */
int io_fd_accept(int fd, int flags, struct sockaddr *addr, socklen_t *addrlen,
		int timeout);

/**
 * Equivalent to POSIX `connect(fd, addr, addrlen)`, except that if <b>fd</b> is
 * non-blocking and <b>dontwait</b> is 0, this function behaves as if <b>fd</b>
 * is blocking.
 */
int io_fd_connect(int fd, const struct sockaddr *addr, socklen_t addrlen,
		int dontwait);

/**
 * Equivalent to POSIX `recvmsg(fd, msg, flags)`, except that if <b>fd</b> is
 * non-blocking (or the implementation supports the `MSG_DONTWAIT` flag) and
 * <b>timeout</b> is non-negative, this function behaves as if <b>fd</b> is
 * blocking and the `SO_RCVTIMEO` option is set with <b>timeout</b>
 * milliseconds. The timeout interval will be rounded up to the system clock
 * granularity, but this function MAY return early if interrupted by a signal.
 */
ssize_t io_fd_recvmsg(int fd, struct msghdr *msg, int flags, int timeout);

/**
 * Equivalent to POSIX `sendmsg(fd, msg, flags | MSG_NOSIGNAL)`, except that if
 * <b>fd</b> is non-blocking (or the implementation supports the `MSG_DONTWAIT`
 * flag) and <b>timeout</b> is non-negative, this function behaves as if
 * <b>fd</b> is blocking and the `SO_SNDTIMEO` option is set with <b>timeout</b>
 * milliseconds. The timeout interval will be rounded up to the system clock
 * granularity, but this function MAY return early if interrupted by a signal.
 */
ssize_t io_fd_sendmsg(int fd, const struct msghdr *msg, int flags, int timeout);

#ifdef __cplusplus
}
#endif

#endif // _POSIX_C_SOURCE >= 200112L

#endif // !LELY_IO2_INTERN_POSIX_FD_H_
