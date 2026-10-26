/* Spawns r2dp-mockfwd on a temp socket and drives the full protocol. */
#include <arpa/inet.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "r2dp/client.h"

static int fails;
#define CHECK(c) do { if (!(c)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); fails++; } } while (0)

static char sockpath[108], dir[64];
static const char *mockbin;

static pid_t spawn(int echo_keys)
{
	pid_t p = fork();
	if (p == 0) {
		if (echo_keys) execl(mockbin, mockbin, "-s", sockpath, "-K", (char *)NULL);
		else           execl(mockbin, mockbin, "-s", sockpath, (char *)NULL);
		_exit(127);
	}
	return p;
}
static int connect_retry(void)
{
	for (int i = 0; i < 100; i++) {
		int fd = r2dp_connect(sockpath);
		if (fd >= 0) return fd;
		usleep(20000);
	}
	return -1;
}
static void stop(pid_t p) { kill(p, SIGTERM); waitpid(p, NULL, 0); }

static int xfer(int fd, unsigned type, uint32_t seq, uint32_t flags, const void *body,
                size_t bl, const void *tail, size_t tl, struct r2dp_msg *rep)
{
	int r = r2dp_send(fd, type, seq, 0, flags, body, bl, tail, tl);
	if (r < 0) return r;
	r = r2dp_recv(fd, rep);
	if (r == 0) { CHECK(rep->h.type == type); CHECK(rep->h.seq == seq); }
	return r;
}

static void v4(struct r2dp_addr *a, const char *ip, int port)
{
	memset(a, 0, sizeof(*a)); a->family = R2DP_AF_INET4;
	inet_pton(AF_INET, ip, a->addr); a->port = htons(port);
}

static void test_sa(int fd, int keys_expected)
{
	struct r2dp_msg rep;
	struct r2dp_sa sa, got;
	uint8_t enc[36], auth[32], tail[68];
	uint32_t spi;

	memset(&sa, 0, sizeof(sa));
	v4(&sa.src, "192.0.2.1", 0); v4(&sa.dst, "192.0.2.2", 0);
	sa.proto = R2DP_PROTO_ESP; sa.mode = R2DP_MODE_TUNNEL; sa.reqid = 42;
	sa.spi_min = 0x1000; sa.spi_max = 0x1fff;

	CHECK(xfer(fd, R2DP_GETSPI, 1, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0);
	spi = r2dp_msg_sa(&rep)->spi;
	CHECK(ntohl(spi) >= 0x1000 && ntohl(spi) <= 0x1fff);

	/* second GETSPI must not hand out the same SPI */
	CHECK(xfer(fd, R2DP_GETSPI, 2, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(r2dp_msg_sa(&rep)->spi != spi);

	/* full SA: GCM-16 (key+salt), ESN, NAT-T, NAT-OA, lifetimes */
	sa.spi = spi; sa.spi_min = sa.spi_max = 0;
	sa.enc = R2DP_ENCR_AES_GCM_16; sa.integ = R2DP_INTEG_NONE;
	sa.saflags = R2DP_SAF_ESN; sa.wsize = 64;
	sa.natt_type = R2DP_NATT_ESPINUDP; sa.natt_sport = htons(4500); sa.natt_dport = htons(4500);
	v4(&sa.natoa_src, "10.9.9.1", 0); v4(&sa.natoa_dst, "10.9.9.2", 0);
	sa.lft_hard_time = 3600; sa.lft_soft_time = 3000;
	sa.lft_hard_bytes = 1ull << 40; sa.lft_soft_bytes = 1ull << 39;
	sa.enckeylen = sizeof(enc); sa.authkeylen = sizeof(auth);
	for (unsigned i = 0; i < sizeof(enc); i++) enc[i] = (uint8_t)(0xa0 + i);
	for (unsigned i = 0; i < sizeof(auth); i++) auth[i] = (uint8_t)(0x10 + i);
	memcpy(tail, enc, sizeof(enc)); memcpy(tail + sizeof(enc), auth, sizeof(auth));

	CHECK(xfer(fd, R2DP_SA_UPDATE, 3, 0, &sa, sizeof(sa), tail, sizeof(tail), &rep) == 0);
	CHECK(rep.h.status == 0);

	CHECK(xfer(fd, R2DP_SA_GET, 4, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0);
	memcpy(&got, r2dp_msg_sa(&rep), sizeof(got));
	CHECK(memcmp(&got, &sa, sizeof(sa)) == 0);            /* every field survives */
	CHECK(got.saflags & R2DP_SAF_ESN);
	CHECK(got.natt_dport == htons(4500) && got.natoa_src.family == R2DP_AF_INET4);
	if (keys_expected) {
		CHECK(!(rep.h.flags & R2DP_HF_NOKEYS));
		CHECK(memcmp(r2dp_msg_enckey(&rep), enc, sizeof(enc)) == 0);
		CHECK(memcmp(r2dp_msg_authkey(&rep), auth, sizeof(auth)) == 0);
	} else {
		CHECK(rep.h.flags & R2DP_HF_NOKEYS);              /* keys never leave by default */
		CHECK(rep.h.len == sizeof(rep.h) + sizeof(struct r2dp_sa));
	}

	/* kernel-like errors */
	CHECK(xfer(fd, R2DP_SA_ADD, 5, 0, &sa, sizeof(sa), tail, sizeof(tail), &rep) == 0);
	CHECK(rep.h.status == EEXIST);
	{ struct r2dp_sa bogus = sa; bogus.spi = htonl(0xdead);
	  CHECK(xfer(fd, R2DP_SA_UPDATE, 6, R2DP_HF_NOKEYS, &bogus, sizeof(bogus), NULL, 0, &rep) == 0);
	  CHECK(rep.h.status == ENOENT); }

	CHECK(xfer(fd, R2DP_SA_DEL, 7, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0);
	CHECK(xfer(fd, R2DP_SA_GET, 8, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == ENOENT);
	CHECK(xfer(fd, R2DP_SA_DEL, 9, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == ENOENT);

	/* SA_ADD without GETSPI works too (responder-less install) */
	CHECK(xfer(fd, R2DP_SA_ADD, 10, 0, &sa, sizeof(sa), tail, sizeof(tail), &rep) == 0);
	CHECK(rep.h.status == 0);
}

static void test_sp(int fd)
{
	struct r2dp_msg rep;
	struct r2dp_sp a, b, got;
	uint32_t slid_a;

	memset(&a, 0, sizeof(a));
	a.dir = R2DP_DIR_OUT; a.ul_proto = R2DP_PROTO_ANY;
	v4(&a.sel_src, "10.0.0.0", 0); v4(&a.sel_dst, "10.0.1.0", 0);
	a.pref_src = a.pref_dst = 24;
	a.action = R2DP_ACT_PROTECT; a.mode = R2DP_MODE_TUNNEL; a.level = R2DP_LVL_REQUIRE;
	a.protos = R2DP_SPP_ESP; a.reqid = 42;
	v4(&a.tun_src, "192.0.2.1", 0); v4(&a.tun_dst, "192.0.2.2", 0);
	a.lft_hard_time = 7200; strcpy(a.tag, "tagA");

	/* empty SPD => ENOENT on dump (kernel behaviour) */
	CHECK(xfer(fd, R2DP_SP_DUMP, 20, 0, &a, sizeof(a), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == ENOENT);

	CHECK(xfer(fd, R2DP_SP_ADD, 21, 0, &a, sizeof(a), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0);
	slid_a = r2dp_msg_sp(&rep)->slid;
	CHECK(slid_a != 0);

	CHECK(xfer(fd, R2DP_SP_ADD, 22, 0, &a, sizeof(a), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == EEXIST);                                  /* same selector */
	a.reqid = 43; a.flags = R2DP_SPF_UPDATE;
	CHECK(xfer(fd, R2DP_SP_ADD, 23, 0, &a, sizeof(a), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0 && r2dp_msg_sp(&rep)->slid == slid_a);  /* upsert keeps id */
	CHECK(r2dp_msg_sp(&rep)->reqid == 43);

	b = a; b.flags = 0; b.dir = R2DP_DIR_IN; b.reqid = 44;
	v4(&b.sel_src, "10.0.1.0", 0); v4(&b.sel_dst, "10.0.0.0", 0);
	b.ul_proto = 6; b.sel_dst.port = htons(443);                    /* port selectors */
	CHECK(xfer(fd, R2DP_SP_ADD, 24, 0, &b, sizeof(b), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0 && r2dp_msg_sp(&rep)->slid != slid_a);

	/* dump: 2 messages, MORE on the first only */
	CHECK(r2dp_send(fd, R2DP_SP_DUMP, 25, 0, 0, &a, sizeof(a), NULL, 0) == 0);
	CHECK(r2dp_recv(fd, &rep) == 0 && (rep.h.flags & R2DP_HF_MORE));
	CHECK(r2dp_recv(fd, &rep) == 0 && !(rep.h.flags & R2DP_HF_MORE));

	/* SP_GET by slid returns every selector field intact */
	memset(&got, 0, sizeof(got)); got.slid = slid_a;
	CHECK(xfer(fd, R2DP_SP_GET, 26, 0, &got, sizeof(got), NULL, 0, &rep) == 0);
	CHECK(rep.h.status == 0);
	got = *r2dp_msg_sp(&rep);
	a.flags = 0; a.slid = slid_a;
	CHECK(memcmp(&got, &a, sizeof(a)) == 0);

	/* delete by slid, then by selector, then ENOENT */
	memset(&got, 0, sizeof(got)); got.slid = slid_a;
	CHECK(xfer(fd, R2DP_SP_DEL, 27, 0, &got, sizeof(got), NULL, 0, &rep) == 0 && rep.h.status == 0);
	CHECK(xfer(fd, R2DP_SP_DEL, 28, 0, &b, sizeof(b), NULL, 0, &rep) == 0 && rep.h.status == 0);
	CHECK(xfer(fd, R2DP_SP_DEL, 29, 0, &b, sizeof(b), NULL, 0, &rep) == 0 && rep.h.status == ENOENT);
}

static void test_protocol_errors(void)
{
	struct r2dp_msg rep;
	struct r2dp_hello_ack ack;
	int fd = connect_retry();

	CHECK(fd >= 0);
	CHECK(r2dp_hello(fd, R2DP_ROLE_CTL, &ack) == 0);
	CHECK(ack.max_msg == R2DP_MAX_MSG && (ack.features & R2DP_FEAT_ESN));
	CHECK(r2dp_cap(ack.enc_caps, R2DP_ENCR_AES_GCM_16));

	/* unknown but well-formed type => ENOSYS completion, connection survives */
	CHECK(r2dp_send(fd, 0x7777, 99, 0, 0, NULL, 0, NULL, 0) == 0);
	CHECK(r2dp_recv(fd, &rep) == -ENOSYS);        /* header valid, type unknown */
	CHECK(rep.h.status == ENOSYS && rep.h.seq == 99);
	/* client sending a forwarder-only type => EPROTO completion */
	{ struct r2dp_sa sa; memset(&sa, 0, sizeof(sa));
	  CHECK(xfer(fd, R2DP_EXPIRE, 100, R2DP_HF_NOKEYS, &sa, sizeof(sa), NULL, 0, &rep) == 0);
	  CHECK(rep.h.status == EPROTO); }
	/* malformed (bad magic) => forwarder drops us */
	{ char junk[40]; memset(junk, 0x5a, sizeof(junk));
	  CHECK(send(fd, junk, sizeof(junk), 0) == (ssize_t)sizeof(junk));
	  CHECK(r2dp_recv(fd, &rep) == -ECONNRESET); }
	close(fd);

	/* ...and the forwarder is still serving others */
	fd = connect_retry();
	CHECK(fd >= 0 && r2dp_hello(fd, R2DP_ROLE_IKED, NULL) == 0);
	close(fd);
}

int main(int argc, char **argv)
{
	pid_t p;
	int fd;

	if (argc < 2) { fprintf(stderr, "usage: %s <r2dp-mockfwd>\n", argv[0]); return 2; }
	mockbin = argv[1];
	snprintf(dir, sizeof(dir), "/tmp/r2dp-test-XXXXXX");
	if (!mkdtemp(dir)) { perror("mkdtemp"); return 2; }
	snprintf(sockpath, sizeof(sockpath), "%s/s", dir);

	/* run 1: -K (keys echoed) ; run 2: default (keys withheld) */
	for (int keys = 1; keys >= 0; keys--) {
		p = spawn(keys);
		fd = connect_retry();
		CHECK(fd >= 0);
		if (fd >= 0) {
			test_sa(fd, keys);
			if (keys) { test_sp(fd); test_protocol_errors(); }
			close(fd);
		}
		stop(p);
	}
	unlink(sockpath); rmdir(dir);

	if (fails) { fprintf(stderr, "%d check(s) failed\n", fails); return 1; }
	puts("test_mock ok");
	return 0;
}
