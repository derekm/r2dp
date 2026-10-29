/* libr2dp: transport, validation and address helpers shared by the
 * racoon2 shim (client) and forwarders (server side). */
#ifndef R2DP_CLIENT_H
#define R2DP_CLIENT_H

#include <stddef.h>
#include <sys/socket.h>
#include "r2dp/proto.h"

struct r2dp_msg {
	struct r2dp_hdr h;
	uint8_t body[R2DP_MAX_MSG - sizeof(struct r2dp_hdr)];
};

/* All functions return 0 / fd >= 0 on success or -errno. */

/* Client: connect to path (NULL => $R2DP_SOCK, then R2DP_DEFAULT_SOCK). */
int r2dp_connect(const char *path);
/* Server: bind+listen a 0600 SOCK_SEQPACKET socket (replaces a stale one). */
int r2dp_listen(const char *path, int backlog);
int r2dp_accept(int lfd);

/* Send hdr + body + tail as one message. */
int r2dp_send(int fd, uint16_t type, uint32_t seq, uint32_t status,
              uint32_t flags, const void *body, size_t blen,
              const void *tail, size_t tlen);

/* Like r2dp_send() but never blocks (MSG_DONTWAIT): for unsolicited events, where a
 * stalled client must not stall the forwarder.  -EAGAIN means the event was dropped. */
int r2dp_send_nowait(int fd, uint16_t type, uint32_t seq, uint32_t status,
                     uint32_t flags, const void *body, size_t blen,
                     const void *tail, size_t tlen);

/*
 * Receive one message and validate it.
 *   0           ok
 *   -ECONNRESET peer closed
 *   -EPROTO     malformed (bad magic/version/length/body); close the peer
 *   -ENOSYS     well-formed header but unknown type; m->h is valid, so a
 *               server can answer with status ENOSYS
 *   -EMSGSIZE   datagram larger than R2DP_MAX_MSG
 */
int r2dp_recv(int fd, struct r2dp_msg *m);

/* Validate n received bytes (used by r2dp_recv; exposed for tests). */
int r2dp_validate(const struct r2dp_msg *m, size_t n);

/* Blocking HELLO handshake; fills *ack. */
int r2dp_hello(int fd, uint32_t role, struct r2dp_hello_ack *ack);

/* Capability bitmap tests (IANA transform id < 256). */
static inline int r2dp_cap(const uint32_t bm[8], unsigned id)
{
	return id < 256 && (bm[id >> 5] >> (id & 31)) & 1u;
}

/* SA message accessors (tail layout: enckey then authkey). */
static inline const struct r2dp_sa *r2dp_msg_sa(const struct r2dp_msg *m)
{ return (const struct r2dp_sa *)m->body; }
static inline const struct r2dp_sp *r2dp_msg_sp(const struct r2dp_msg *m)
{ return (const struct r2dp_sp *)m->body; }
static inline const uint8_t *r2dp_msg_enckey(const struct r2dp_msg *m)
{ return m->body + sizeof(struct r2dp_sa); }
static inline const uint8_t *r2dp_msg_authkey(const struct r2dp_msg *m)
{ return m->body + sizeof(struct r2dp_sa) + r2dp_msg_sa(m)->enckeylen; }

/* sockaddr <-> wire address.  from_sa(NULL) yields UNSET.  to_sa returns
 * 0 on success, 1 if the address is UNSET, -EAFNOSUPPORT otherwise. */
int r2dp_addr_from_sa(struct r2dp_addr *a, const struct sockaddr *sa);
int r2dp_addr_to_sa(const struct r2dp_addr *a, struct sockaddr_storage *ss);
int r2dp_addr_eq(const struct r2dp_addr *a, const struct r2dp_addr *b); /* family+addr, not port */

const char *r2dp_msg_name(unsigned type);

#endif
