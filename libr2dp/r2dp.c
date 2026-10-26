#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <netinet/in.h>
#include "r2dp/client.h"

/* ------------------------------------------------------------ transport */
static int mksock(void)
{
	int fd;
#ifdef SOCK_CLOEXEC
	fd = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
#else
	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	return fd < 0 ? -errno : fd;
}

static int fillun(struct sockaddr_un *un, const char *path)
{
	if (!path) path = getenv(R2DP_ENV_SOCK);
	if (!path || !*path) path = R2DP_DEFAULT_SOCK;
	if (strlen(path) >= sizeof(un->sun_path)) return -ENAMETOOLONG;
	memset(un, 0, sizeof(*un));
	un->sun_family = AF_UNIX;
	strcpy(un->sun_path, path);
	return 0;
}

int r2dp_connect(const char *path)
{
	struct sockaddr_un un;
	int fd, r;
	if ((r = fillun(&un, path)) < 0) return r;
	if ((fd = mksock()) < 0) return fd;
	if (connect(fd, (struct sockaddr *)&un, sizeof(un)) < 0) {
		r = -errno; close(fd); return r;
	}
	return fd;
}

int r2dp_listen(const char *path, int backlog)
{
	struct sockaddr_un un;
	struct stat st;
	mode_t old;
	int fd, r;
	if ((r = fillun(&un, path)) < 0) return r;
	if ((fd = mksock()) < 0) return fd;
	if (lstat(un.sun_path, &st) == 0 && S_ISSOCK(st.st_mode))
		unlink(un.sun_path);
	old = umask(077);
	r = bind(fd, (struct sockaddr *)&un, sizeof(un));
	umask(old);
	if (r < 0 || listen(fd, backlog) < 0) {
		r = -errno; close(fd); return r;
	}
	return fd;
}

int r2dp_accept(int lfd)
{
	int fd;
#ifdef __linux__
	fd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
#else
	fd = accept(lfd, NULL, NULL);
	if (fd >= 0) fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	return fd < 0 ? -errno : fd;
}

int r2dp_send(int fd, uint16_t type, uint32_t seq, uint32_t status,
              uint32_t flags, const void *body, size_t blen,
              const void *tail, size_t tlen)
{
	struct r2dp_hdr h;
	struct iovec iov[3];
	struct msghdr mh;
	size_t total = sizeof(h) + blen + tlen;
	ssize_t n;
	int i = 0;

	if (total > R2DP_MAX_MSG) return -EMSGSIZE;
	h.magic = R2DP_MAGIC; h.version = R2DP_VERSION; h.type = type;
	h.len = (uint32_t)total; h.seq = seq; h.status = status; h.flags = flags;
	iov[i].iov_base = &h; iov[i++].iov_len = sizeof(h);
	if (blen) { iov[i].iov_base = (void *)body; iov[i++].iov_len = blen; }
	if (tlen) { iov[i].iov_base = (void *)tail; iov[i++].iov_len = tlen; }
	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = iov; mh.msg_iovlen = i;
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
	do n = sendmsg(fd, &mh, MSG_NOSIGNAL); while (n < 0 && errno == EINTR);
	if (n < 0) return -errno;
	return (size_t)n == total ? 0 : -EIO;
}

/* ----------------------------------------------------------- validation */
static int body_size(unsigned type, size_t *min)
{
	switch (type) {
	case R2DP_HELLO:     *min = sizeof(struct r2dp_hello); return 0;
	case R2DP_HELLO_ACK: *min = sizeof(struct r2dp_hello_ack); return 0;
	case R2DP_GETSPI: case R2DP_SA_ADD: case R2DP_SA_UPDATE:
	case R2DP_SA_DEL: case R2DP_SA_GET: case R2DP_EXPIRE: case R2DP_ACQUIRE:
		*min = sizeof(struct r2dp_sa); return 1;   /* 1 = SA (key tail) */
	case R2DP_SP_ADD: case R2DP_SP_DEL: case R2DP_SP_GET: case R2DP_SP_DUMP:
		*min = sizeof(struct r2dp_sp); return 0;
	}
	return -1;
}

int r2dp_validate(const struct r2dp_msg *m, size_t n)
{
	size_t min, bodylen;
	int kind;

	if (n < sizeof(m->h)) return -EPROTO;
	if (m->h.magic != R2DP_MAGIC || m->h.version != R2DP_VERSION) return -EPROTO;
	if (m->h.len != n || n > R2DP_MAX_MSG) return -EPROTO;
	if ((kind = body_size(m->h.type, &min)) < 0) return -ENOSYS;
	bodylen = n - sizeof(m->h);
	if (bodylen < min) return -EPROTO;
	if (kind == 1) {
		const struct r2dp_sa *sa = (const struct r2dp_sa *)m->body;
		size_t tail = bodylen - min;
		if (sa->enckeylen > R2DP_MAX_KEY || sa->authkeylen > R2DP_MAX_KEY)
			return -EPROTO;
		if (m->h.flags & R2DP_HF_NOKEYS) {
			if (tail != 0) return -EPROTO;
		} else if (tail != (size_t)sa->enckeylen + sa->authkeylen) {
			return -EPROTO;
		}
	} else if (bodylen != min) {
		return -EPROTO;
	}
	return 0;
}

int r2dp_recv(int fd, struct r2dp_msg *m)
{
	struct iovec iov = { m, sizeof(*m) };
	struct msghdr mh;
	ssize_t n;

	memset(&mh, 0, sizeof(mh));
	mh.msg_iov = &iov; mh.msg_iovlen = 1;
	do n = recvmsg(fd, &mh, 0); while (n < 0 && errno == EINTR);
	if (n < 0) return -errno;
	if (n == 0) return -ECONNRESET;
	if (mh.msg_flags & MSG_TRUNC) return -EMSGSIZE;
	return r2dp_validate(m, (size_t)n);
}

int r2dp_hello(int fd, uint32_t role, struct r2dp_hello_ack *ack)
{
	struct r2dp_hello h;
	struct r2dp_msg m;
	int r;

	memset(&h, 0, sizeof(h));
	h.role = role; h.pid = (uint32_t)getpid();
	if ((r = r2dp_send(fd, R2DP_HELLO, 0, 0, 0, &h, sizeof(h), NULL, 0)) < 0)
		return r;
	if ((r = r2dp_recv(fd, &m)) < 0) return r;
	if (m.h.type != R2DP_HELLO_ACK) return -EPROTO;
	if (m.h.status) return -(int)m.h.status;
	if (ack) memcpy(ack, m.body, sizeof(*ack));
	return 0;
}

/* ------------------------------------------------------------ addresses */
int r2dp_addr_from_sa(struct r2dp_addr *a, const struct sockaddr *sa)
{
	memset(a, 0, sizeof(*a));
	if (!sa) return 0;
	switch (sa->sa_family) {
	case AF_INET: {
		const struct sockaddr_in *s = (const void *)sa;
		a->family = R2DP_AF_INET4; a->port = s->sin_port;
		memcpy(a->addr, &s->sin_addr, 4);
		return 0; }
	case AF_INET6: {
		const struct sockaddr_in6 *s = (const void *)sa;
		a->family = R2DP_AF_INET6; a->port = s->sin6_port;
		a->scope = s->sin6_scope_id;
		memcpy(a->addr, &s->sin6_addr, 16);
		return 0; }
	}
	return -EAFNOSUPPORT;
}

int r2dp_addr_to_sa(const struct r2dp_addr *a, struct sockaddr_storage *ss)
{
	memset(ss, 0, sizeof(*ss));
	switch (a->family) {
	case R2DP_AF_UNSET: return 1;
	case R2DP_AF_INET4: {
		struct sockaddr_in *s = (void *)ss;
#ifdef HAVE_SA_LEN
		s->sin_len = sizeof(*s);
#endif
		s->sin_family = AF_INET; s->sin_port = a->port;
		memcpy(&s->sin_addr, a->addr, 4);
		return 0; }
	case R2DP_AF_INET6: {
		struct sockaddr_in6 *s = (void *)ss;
#ifdef HAVE_SA_LEN
		s->sin6_len = sizeof(*s);
#endif
		s->sin6_family = AF_INET6; s->sin6_port = a->port;
		s->sin6_scope_id = a->scope;
		memcpy(&s->sin6_addr, a->addr, 16);
		return 0; }
	}
	return -EAFNOSUPPORT;
}

int r2dp_addr_eq(const struct r2dp_addr *a, const struct r2dp_addr *b)
{
	size_t n = a->family == R2DP_AF_INET4 ? 4 : a->family == R2DP_AF_INET6 ? 16 : 0;
	return a->family == b->family && memcmp(a->addr, b->addr, n) == 0;
}

const char *r2dp_msg_name(unsigned t)
{
	static const char *const n[] = { "?", "HELLO", "HELLO_ACK", "GETSPI",
		"SA_ADD", "SA_UPDATE", "SA_DEL", "SA_GET", "SP_ADD", "SP_DEL",
		"SP_GET", "SP_DUMP", "EXPIRE", "ACQUIRE" };
	return t < R2DP_MSG_MAX ? n[t] : "?";
}
