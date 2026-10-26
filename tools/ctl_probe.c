/* ctl_probe: connect to a running r2dp-fwd, GETSPI->SA_ADD an inbound SA and
 * SP_ADD one policy, then exit.  Pair with `r2dpctl dump` to prove the dump
 * matches the forwarder's SAD/SPD (M1 exit gate).  Usage: ctl_probe [sock]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "r2dp/client.h"

static int
rt(int fd, uint16_t type, const void *body, size_t blen,
    const void *tail, size_t tlen, struct r2dp_msg *reply)
{
	uint32_t seq = (uint32_t)type;
	int r;
	if ((r = r2dp_send(fd, type, seq, 0, 0, body, blen, tail, tlen)) < 0)
		return r;
	for (;;) {
		struct r2dp_msg m;
		r = r2dp_recv(fd, &m);
		if (r < 0) return r;
		if (m.h.seq == seq && m.h.type == type) {
			if (reply) *reply = m;
			return m.h.status ? -(int)m.h.status : 0;
		}
	}
}

int
main(int argc, char **argv)
{
	const char *sock = argc > 1 ? argv[1]
	    : (getenv("R2DP_SOCK") ? getenv("R2DP_SOCK") : "/var/run/r2dp.sock");
	struct r2dp_hello_ack ack;
	struct r2dp_msg reply;
	struct r2dp_sa sa;
	struct r2dp_sp sp;
	uint8_t blob[20];
	int fd, r;

	fd = r2dp_connect(sock);
	if (fd < 0) { fprintf(stderr, "connect: %s\n", strerror(-fd)); return 2; }
	if ((r = r2dp_hello(fd, R2DP_ROLE_IKED, &ack)) < 0) {
		fprintf(stderr, "hello: %s\n", strerror(-r)); return 2; }

	memset(&sa, 0, sizeof(sa));
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL;
	sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
	sa.spi_min = 0x4000; sa.spi_max = 0x4fff;
	sa.dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "10.0.0.2", sa.dst.addr);

	if ((r = rt(fd, R2DP_GETSPI, &sa, sizeof(sa), NULL, 0, &reply)) < 0) {
		fprintf(stderr, "getspi: %s\n", strerror(-r)); return 2; }
	sa.spi = r2dp_msg_sa(&reply)->spi;
	memset(blob, 0xAB, sizeof(blob));
	sa.enckeylen = sizeof(blob); sa.authkeylen = 0;
	if ((r = rt(fd, R2DP_SA_ADD, &sa, sizeof(sa), blob, sizeof(blob), &reply)) < 0) {
		fprintf(stderr, "sa_add: %s\n", strerror(-r)); return 2; }
	printf("installed SA spi=0x%08x dst=10.0.0.2\n", ntohl(sa.spi));

	memset(&sp, 0, sizeof(sp));
	sp.dir = R2DP_DIR_OUT; sp.action = R2DP_ACT_PROTECT; sp.mode = R2DP_MODE_TUNNEL;
	sp.ul_proto = R2DP_PROTO_ESP; sp.slid = 0;
	sp.sel_src.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.0", sp.sel_src.addr);
	sp.sel_dst.family = R2DP_AF_INET4;
	inet_pton(AF_INET, "192.0.2.0", sp.sel_dst.addr);
	sp.pref_src = 24; sp.pref_dst = 24;
	if ((r = rt(fd, R2DP_SP_ADD, &sp, sizeof(sp), NULL, 0, &reply)) < 0) {
		fprintf(stderr, "sp_add: %s\n", strerror(-r)); return 2; }
	printf("installed SP slid=%u\n", r2dp_msg_sp(&reply)->slid);
	close(fd);
	return 0;
}
