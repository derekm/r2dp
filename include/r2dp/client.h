/*
 * r2dp client/server library API.
 *
 * The wire contract lives in <r2dp/proto.h>.  This header declares the
 * transport + validation helpers shared by a client (racoon2 shim) and a
 * server (r2dp-mockfwd, later the DPDK forwarder): connect/listen/accept,
 * send/recv a single framed message, capability querying, message accessors,
 * and address <-> sockaddr conversion.
 *
 * Transport is AF_UNIX SOCK_SEQPACKET, one message per datagram, host
 * endian (local only).  All functions either return a value >= 0 on success
 * or a negative errno on failure.
 */
#ifndef R2DP_CLIENT_H
#define R2DP_CLIENT_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

#include "r2dp/proto.h"

/* Number of u32 words in a capability bitmap (enc_caps / integ_caps). */
#define R2DP_CAP_WORDS 8

/*
 * One received message: header + variable body.  `body` holds the payload
 * (struct r2dp_hello / r2dp_sa / r2dp_sp / r2dp_hello_ack depending on type)
 * followed by the optional key tail for SA messages.  Access via the
 * r2dp_msg_* accessors.  Fixed at R2DP_MAX_MSG so the receiver can `read`
 * into it on SOCK_SEQPACKET.
 */
struct r2dp_msg {
	struct r2dp_hdr h;
	uint8_t         body[R2DP_MAX_MSG - sizeof(struct r2dp_hdr)];
};

/* ---- transport -------------------------------------------------------- */
/* Connect to the forwarder at `path` (NULL => $R2DP_SOCK else default).
 * Returns fd on success, or a negative errno. */
int r2dp_connect(const char *path);

/* Bind+listen a unix SOCK_SEQPACKET endpoint at `path` for the forwarder.
 * Returns listener fd or a negative errno. */
int r2dp_listen(const char *path, int backlog);

/* Accept one client.  Returns fd or a negative errno. */
int r2dp_accept(int lfd);

/* Reconnect-safe: replace `*fd` with a fresh connection (M4 resync). */
int r2dp_reconnect(const char *path, int *fd);

/* ---- messaging -------------------------------------------------------- */
/*
 * Send one framed message: hdr + body[blen] + tail[tlen].
 * `type` is an r2dp_msg_type, `seq` is echoed in the completion.
 * `status` is errno-style (0 = ok); on requests this is always 0.
 * Returns 0 or a negative errno.
 */
int r2dp_send(int fd, uint16_t type, uint32_t seq, int status, uint32_t flags,
              const void *body, size_t blen, const void *tail, size_t tlen);

/*
 * Receive one complete message into `m`.  `m` must be at least as large as
 * R2DP_MAX_MSG (use R2DP_MSG_INIT / sizeof below).
 * Returns:
 *   0      on success
 *   -ENOSYS if the type is unknown (newer forwarder) -- body already parsed
 *   a negative errno otherwise (EBADMSG on parse failure, etc.)
 */
int r2dp_recv(int fd, struct r2dp_msg *m);

/* Size a receiver buffer for r2dp_recv. */
#define R2DP_MSG_INIT() ((struct r2dp_msg){ 0 })

/* ---- handshake / capabilities ---------------------------------------- */
/*
 * Perform the HELLO handshake: send a HELLO for `role` and read the
 * HELLO_ACK into `*ack`.  Returns 0 or a negative errno.
 */
int r2dp_hello(int fd, uint32_t role, struct r2dp_hello_ack *ack);

/* Whether capability set `caps` (r2dp_hello_ack.enc_caps / integ_caps)
 * advertises transform id `id`. */
int r2dp_cap(const uint32_t caps[R2DP_CAP_WORDS], unsigned id);

/* Human name for a message type (for logs); "?" if unknown. */
const char *r2dp_msg_name(uint16_t type);

/* ---- message accessors ------------------------------------------------ */
/* Body of a message typed as SA / SP (caller checks the type first). */
const struct r2dp_sa *r2dp_msg_sa(const struct r2dp_msg *m);
const struct r2dp_sp *r2dp_msg_sp(const struct r2dp_msg *m);
/* SA key tail accessors.  Only meaningful when R2DP_HF_NOKEYS is NOT set. */
const uint8_t *r2dp_msg_enckey(const struct r2dp_msg *m);
const uint8_t *r2dp_msg_authkey(const struct r2dp_msg *m);

/* ---- address helpers -------------------------------------------------- */
/* Convert a sockaddr to a wire r2dp_addr.  Returns 0 or a negative errno
 * (EAFNOSUPPORT for an unsupported family). */
int r2dp_addr_from_sa(struct r2dp_addr *a, const struct sockaddr *sa);

/* Convert a wire r2dp_addr to a sockaddr_storage.  Returns 0 or a negative
 * errno (EAFNOSUPPORT for R2DP_AF_UNSET / unknown). */
int r2dp_addr_to_sa(const struct r2dp_addr *a, struct sockaddr_storage *st);

/* Whether two wire addresses denote the same endpoint (family + address +
 * scope; ports are compared by callers when relevant). */
int r2dp_addr_eq(const struct r2dp_addr *a, const struct r2dp_addr *b);

#endif /* R2DP_CLIENT_H */
