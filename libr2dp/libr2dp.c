/*
 * libr2dp: transport, validation, and address helpers for the r2dp control
 * protocol (see <r2dp/proto.h> for the wire contract, <r2dp/client.h> for
 * this API).
 *
 * Reconstructed for the original M0 from the wire contract in proto.h plus
 * the calls made by shim/if_r2dp.c (racoon2 backend) and tools/mockfwd.c
 * (protocol-faithful forwarder).
 */
#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>

#include "r2dp/client.h"

/* Default socket path and environment override. */
#define R2DP_SOCK_ENV "R2DP_SOCK"

static const char *
sock_path(const char *path)
{
	const char *e;

	if (path != NULL)
		return path;
	e = getenv(R2DP_SOCK_ENV);
	return e ? e : R2DP_DEFAULT_SOCK;
}

/* ------------------------------------------------------------------ */
int
r2dp_connect(const char *path)
{
	struct sockaddr_un un;
	const char *p = sock_path(path);
	int fd;

	if (strlen(p) >= sizeof(un.sun_path))
		return -ENAMETOOLONG;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, p, sizeof(un.sun_path) - 1);
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}

int
r2dp_listen(const char *path, int backlog)
{
	struct sockaddr_un un;
	struct stat st;
	const char *p = sock_path(path);
	int fd;

	if (strlen(p) >= sizeof(un.sun_path))
		return -ENAMETOOLONG;
	/* Only remove the stale path if it is actually a socket; never blindly
	 * unlink an arbitrary file a caller (or attacker) points us at. */
	if (lstat(p, &st) == 0) {
		if (!S_ISSOCK(st.st_mode))
			return -EEXIST;
		if (unlink(p) < 0)
			return -errno;
	} else if (errno != ENOENT)
		return -errno;
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return -errno;
	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, p, sizeof(un.sun_path) - 1);
	if (bind(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	/* The control socket governs the dataplane: restrict it to the owner
	 * (root by default) so no local user can reach it.  The 0600 mode also
	 * survives the default umask. */
	if (chmod(p, 0600) < 0) {
		int e = errno;
		close(fd);
		unlink(p);
		return -e;
	}
	if (listen(fd, backlog) < 0) {
		int e = errno;
		close(fd);
		return -e;
	}
	return fd;
}

int
r2dp_accept(int lfd)
{
	int fd = accept(lfd, NULL, NULL);

	return fd < 0 ? -errno : fd;
}

int
r2dp_reconnect(const char *path, int *fd)
{
	int nfd;

	if (fd == NULL)
		return -EINVAL;
	nfd = r2dp_connect(path);
	if (nfd < 0)
		return nfd;
	if (*fd >= 0)
		close(*fd);
	*fd = nfd;
	return 0;
}

/* ------------------------------------------------------------------ */
int
r2dp_send(int fd, uint16_t type, uint32_t seq, int status, uint32_t flags,
    const void *body, size_t blen, const void *tail, size_t tlen)
{
	uint8_t buf[R2DP_MAX_MSG];
	struct r2dp_hdr h;
	size_t total = sizeof(h) + blen + tlen;

	if (R2DP_MAX_MSG < total || R2DP_MAX_MSG - sizeof(h) < blen + tlen)
		return -EMSGSIZE;
	memset(&h, 0, sizeof(h));
	h.magic   = R2DP_MAGIC;
	h.version = R2DP_VERSION;
	h.type    = type;
	h.len     = (uint32_t)total;
	h.seq     = seq;
	h.status  = (uint32_t)status;
	h.flags   = flags;
	memcpy(buf, &h, sizeof(h));
	if (blen)
		memcpy(buf + sizeof(h), body, blen);
	if (tlen)
		memcpy(buf + sizeof(h) + blen, tail, tlen);
	/* send(MSG_NOSIGNAL): a vanished peer must surface as -EPIPE, not
	 * SIGPIPE-kill the daemon. */
	errno = 0;
	{
		ssize_t w = send(fd, buf, total, MSG_NOSIGNAL);
		int e = errno;
		/* The staging buffer may hold SA key material: scrub it on every
		 * path so keys never linger on the stack. */
		explicit_bzero(buf, total);
		if (w != (ssize_t)total) {
			/* A short/partial write on a SEQPACKET socket is an I/O
			 * error; map errno (send may leave it 0 on a short write). */
			return (e ? -e : -EIO);
		}
	}
	return 0;
}

int
r2dp_msg_validate(const struct r2dp_msg *m, size_t n)
{
	const struct r2dp_sa *sa;
	size_t hdr = sizeof(m->h);
	size_t body, tail, min;
	uint16_t el, al;

	if (n < hdr)
		return -EBADMSG;
	body = n - hdr;

	if (m->h.flags & ~(R2DP_HF_MORE | R2DP_HF_NOKEYS))
		return -EBADMSG;   /* unknown flag bits (forward-compat guard) */

	switch (m->h.type) {
	case R2DP_HELLO:
		min = sizeof(struct r2dp_hello);
		break;
	case R2DP_HELLO_ACK:
		min = sizeof(struct r2dp_hello_ack);
		break;
	case R2DP_GETSPI:
	case R2DP_SA_ADD:
	case R2DP_SA_UPDATE:
	case R2DP_SA_DEL:
	case R2DP_SA_GET:
	case R2DP_EXPIRE:
	case R2DP_ACQUIRE:
		min = sizeof(struct r2dp_sa);
		break;
	case R2DP_SP_ADD:
	case R2DP_SP_DEL:
	case R2DP_SP_GET:
	case R2DP_SP_DUMP:
		min = sizeof(struct r2dp_sp);
		break;
	default:
		return -EBADMSG;   /* unknown type: caller reports -ENOSYS */
	}
	if (body < min)
		return -EBADMSG;   /* body shorter than the required struct */

	/* SA messages carry a key tail strictly equal to enckeylen+authkeylen
	 * (absent when HF_NOKEYS) -- for EVERY SA type (GETSPI, EXPIRE and
	 * ACQUIRE included), because consumers reconstruct the key blob from
	 * enckeylen/authkeylen on any non-NOKEYS SA.  A peer-controlled
	 * enckeylen must never be able to make them read past the received
	 * bytes.  With NOKEYS the tail must be absent and enckeylen/authkeylen
	 * are not trusted. */
	switch (m->h.type) {
	case R2DP_GETSPI:
	case R2DP_SA_ADD:
	case R2DP_SA_UPDATE:
	case R2DP_SA_GET:
	case R2DP_SA_DEL:
	case R2DP_EXPIRE:
	case R2DP_ACQUIRE:
		sa = (const struct r2dp_sa *)m->body;
		tail = body - sizeof(struct r2dp_sa);
		if (m->h.flags & R2DP_HF_NOKEYS)
			return tail == 0 ? 0 : -EBADMSG;
		el = sa->enckeylen;
		al = sa->authkeylen;
		if (el > R2DP_MAX_KEY || al > R2DP_MAX_KEY)
			return -EBADMSG;
		return tail == (size_t)el + al ? 0 : -EBADMSG;
	default:
		return 0;
	}
}

int
r2dp_recv(int fd, struct r2dp_msg *m)
{
	ssize_t n;
	int r;

	do {
		n = read(fd, m, sizeof(*m));
	} while (n < 0 && errno == EINTR);
	if (n < 0)
		return -errno;
	if (n < (ssize_t)sizeof(m->h))
		return -EBADMSG;
	if (m->h.magic != R2DP_MAGIC)
		return -EBADMSG;
	if (m->h.version != R2DP_VERSION)
		return -EPROTO;
	/* h.len is the total datagram size (header + body + tail); it is the
	 * peer's claim about how many bytes it sent, so match it against what
	 * we actually read.  A mismatch means a short/oversized datagram. */
	if ((size_t)m->h.len != (size_t)n)
		return -EBADMSG;
	r = r2dp_msg_validate(m, (size_t)n);
	/* Unknown type from a newer forwarder: parse the header, signal -ENOSYS. */
	if (m->h.type >= R2DP_MSG_MAX)
		return -ENOSYS;
	return r;
}

/* HELLO uses its own fixed seq so its ACK can be told apart from anything
 * else already queued on the socket. */
#define R2DP_HELLO_SEQ 0x48454c4fu   /* "HELO" */

static long long
now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

int
r2dp_hello(int fd, uint32_t role, struct r2dp_hello_ack *ack)
{
	struct r2dp_hello hello;
	struct r2dp_msg m;
	long long deadline;
	int r;

	memset(&hello, 0, sizeof(hello));
	hello.role = role;
	hello.pid = (uint32_t)getpid();
	r = r2dp_send(fd, R2DP_HELLO, R2DP_HELLO_SEQ, 0, 0, &hello,
	    sizeof(hello), NULL, 0);
	if (r < 0)
		return r;
	/* Bound the handshake: a hung forwarder must not freeze iked/spmd at
	 * startup forever.  Unsolicited EXPIRE/ACQUIRE (or an unknown type
	 * from a newer forwarder) that races ahead of the ACK is skipped; any
	 * other message, or an ACK for another seq, is a protocol error. */
	deadline = now_ms() + R2DP_HELLO_TIMEOUT_MS;
	for (;;) {
		struct pollfd pfd = { .fd = fd, .events = POLLIN };
		long long left = deadline - now_ms();
		int pr;

		if (left <= 0)
			return -ETIMEDOUT;
		do {
			pr = poll(&pfd, 1, (int)left);
		} while (pr < 0 && errno == EINTR);
		if (pr == 0)
			return -ETIMEDOUT;
		if (pr < 0)
			return -errno;
		memset(&m, 0, sizeof(m));
		r = r2dp_recv(fd, &m);
		if (r == -ENOSYS)
			continue;
		if (r < 0)
			return r;
		if (m.h.type == R2DP_EXPIRE || m.h.type == R2DP_ACQUIRE)
			continue;
		if (m.h.type != R2DP_HELLO_ACK || m.h.seq != R2DP_HELLO_SEQ)
			return -EPROTO;
		break;
	}
	if (m.h.status != 0)
		/* errno-style status; anything out of range is a bad peer */
		return (m.h.status < 4096) ? -(int)m.h.status : -EPROTO;
	if (ack != NULL)
		memcpy(ack, m.body, sizeof(*ack));
	return 0;
}

int
r2dp_cap(const uint32_t caps[R2DP_CAP_WORDS], unsigned id)
{
	unsigned word = id / 32, bit = id % 32;

	if (word >= R2DP_CAP_WORDS)
		return 0;
	return (int)((caps[word] >> bit) & 1u);
}

const char *
r2dp_msg_name(uint16_t type)
{
	static const char *const names[R2DP_MSG_MAX] = {
		[R2DP_HELLO]     = "HELLO",
		[R2DP_HELLO_ACK] = "HELLO_ACK",
		[R2DP_GETSPI]    = "GETSPI",
		[R2DP_SA_ADD]    = "SA_ADD",
		[R2DP_SA_UPDATE] = "SA_UPDATE",
		[R2DP_SA_DEL]    = "SA_DEL",
		[R2DP_SA_GET]    = "SA_GET",
		[R2DP_SP_ADD]    = "SP_ADD",
		[R2DP_SP_DEL]    = "SP_DEL",
		[R2DP_SP_GET]    = "SP_GET",
		[R2DP_SP_DUMP]   = "SP_DUMP",
		[R2DP_EXPIRE]    = "EXPIRE",
		[R2DP_ACQUIRE]   = "ACQUIRE",
	};
	return type < R2DP_MSG_MAX && names[type] ? names[type] : "?";
}

const struct r2dp_sa *
r2dp_msg_sa(const struct r2dp_msg *m)
{
	return (const struct r2dp_sa *)m->body;
}

const struct r2dp_sp *
r2dp_msg_sp(const struct r2dp_msg *m)
{
	return (const struct r2dp_sp *)m->body;
}

const uint8_t *
r2dp_msg_enckey(const struct r2dp_msg *m)
{
	return m->body + sizeof(struct r2dp_sa);
}

const uint8_t *
r2dp_msg_authkey(const struct r2dp_msg *m)
{
	const struct r2dp_sa *sa = r2dp_msg_sa(m);

	return m->body + sizeof(struct r2dp_sa) + sa->enckeylen;
}

/* ------------------------------------------------------------------ */
int
r2dp_addr_from_sa(struct r2dp_addr *a, const struct sockaddr *sa)
{
	if (sa == NULL)
		return -EAFNOSUPPORT;
	memset(a, 0, sizeof(*a));
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *in = (const void *)sa;
		a->family = R2DP_AF_INET4;
		a->port = in->sin_port;
		memcpy(a->addr, &in->sin_addr, 4);
		return 0;
	}
	case AF_INET6: {
		const struct sockaddr_in6 *in6 = (const void *)sa;
		a->family = R2DP_AF_INET6;
		a->port = in6->sin6_port;
		a->scope = in6->sin6_scope_id;
		memcpy(a->addr, &in6->sin6_addr, 16);
		return 0;
	}
	default:
		return -EAFNOSUPPORT;
	}
}

int
r2dp_addr_to_sa(const struct r2dp_addr *a, struct sockaddr_storage *st)
{
	if (st == NULL)
		return -EINVAL;
	memset(st, 0, sizeof(*st));
	switch (a->family) {
	case R2DP_AF_INET4: {
		struct sockaddr_in *in = (void *)st;
		in->sin_family = AF_INET;
		in->sin_port = a->port;
		memcpy(&in->sin_addr, a->addr, 4);
		return 0;
	}
	case R2DP_AF_INET6: {
		struct sockaddr_in6 *in6 = (void *)st;
		in6->sin6_family = AF_INET6;
		in6->sin6_port = a->port;
		in6->sin6_scope_id = a->scope;
		memcpy(&in6->sin6_addr, a->addr, 16);
		return 0;
	}
	default:
		return -EAFNOSUPPORT;
	}
}

int
r2dp_addr_eq(const struct r2dp_addr *a, const struct r2dp_addr *b)
{
	if (a->family != b->family || a->scope != b->scope)
		return 0;
	switch (a->family) {
	case R2DP_AF_INET4:
		return memcmp(a->addr, b->addr, 4) == 0;
	case R2DP_AF_INET6:
		return memcmp(a->addr, b->addr, 16) == 0;
	default:
		return 0;
	}
}
