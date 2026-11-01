/*
 * fwd/dpdk_nh.c -- per-peer next-hop table (see dpdk_nh.h).
 */
#ifdef R2DP_HAVE_DPDK
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <rte_errno.h>
#include <rte_hash_crc.h>
#include <rte_malloc.h>

#include "dpdk_nh.h"

static uint64_t
mac_pack(const uint8_t mac[6])
{
	uint64_t v = 0;

	/* the MAC is the word's first 6 bytes in memory order; byte 6 is set
	 * so a learned entry's data is never NULL */
	memcpy(&v, mac, 6);
	((uint8_t *)&v)[6] = 1;
	return v;
}

static struct rte_hash *
nh_create(struct r2dp_nh_tab *t, uint32_t cap)
{
	struct rte_hash_parameters hp;
	struct rte_hash *h;
	char name[RTE_HASH_NAMESIZE];

	snprintf(name, sizeof(name), "%s.%u", t->name, t->gen++);
	memset(&hp, 0, sizeof(hp));
	hp.name = name;
	hp.entries = cap;
	hp.key_len = sizeof(uint32_t);
	hp.hash_func = rte_hash_crc;
	hp.socket_id = t->socket;
	hp.extra_flag = RTE_HASH_EXTRA_FLAGS_RW_CONCURRENCY_LF;
	h = rte_hash_create(&hp);
	if (h && t->rcu) {
		struct rte_hash_rcu_config rc;

		memset(&rc, 0, sizeof(rc));
		rc.v = t->rcu;
		rc.mode = RTE_HASH_QSBR_MODE_DQ;
		if (rte_hash_rcu_qsbr_add(h, &rc) != 0) {
			rte_hash_free(h);
			h = NULL;
		}
	}
	return h;
}

int
r2dp_nh_init(struct r2dp_nh_tab *t, const char *name, uint32_t size,
    struct rte_rcu_qsbr *rcu, int socket)
{
	char rn[RTE_RING_NAMESIZE];

	memset(t, 0, sizeof(*t));
	rte_spinlock_init(&t->lock);
	if (!size)
		size = R2DP_NH_DEFAULT_SIZE;
	if (size < R2DP_NH_MIN_SIZE)
		size = R2DP_NH_MIN_SIZE;
	if (size > R2DP_NH_MAX_CAP)
		return -EINVAL;
	snprintf(t->name, sizeof(t->name), "%s", name);
	t->rcu = rcu;
	t->socket = socket;
	t->h = nh_create(t, size);
	snprintf(rn, sizeof(rn), "%s.q", name);
	t->req = rte_ring_create_elem(rn, sizeof(struct r2dp_nh_req),
	    R2DP_NH_RING_SZ, socket, RING_F_SC_DEQ);
	t->pend = rte_zmalloc_socket("r2dp_nh_pend",
	    R2DP_NH_PEND_MAX * sizeof(*t->pend), 0, socket);
	if (!t->h || !t->req || !t->pend) {
		r2dp_nh_free(t);
		return -ENOMEM;
	}
	t->cap = size;
	return 0;
}

void
r2dp_nh_free(struct r2dp_nh_tab *t)
{
	r2dp_nh_stop(t);
	rte_hash_free(t->h);
	rte_ring_free(t->req);
	rte_free(t->pend);
	t->h = NULL;
	t->req = NULL;
	t->pend = NULL;
}

/* Insert or update under t->lock.  0 unchanged, 1 new, 2 changed,
 * -ENOSPC full (nothing changed). */
static int
nh_put(struct r2dp_nh_tab *t, uint32_t ip, uint64_t m)
{
	void *data;
	int r;

	if (rte_hash_lookup_data(t->h, &ip, &data) >= 0) {
		if ((uint64_t)(uintptr_t)data == m)
			return 0;
		/* MAC change: the data word is replaced atomically in place */
		return rte_hash_add_key_data(t->h, &ip,
		    (void *)(uintptr_t)m) == 0 ? 2 : -ENOSPC;
	}
	r = rte_hash_add_key_data(t->h, &ip, (void *)(uintptr_t)m);
	if (r < 0) {
		t->want_grow = 1;
		return -ENOSPC;
	}
	t->n++;
	if ((uint64_t)t->n * 4 >= (uint64_t)t->cap * 3)
		t->want_grow = 1;
	return 1;
}

static int
nh_enqueue(struct r2dp_nh_tab *t, uint32_t ip, uint64_t m)
{
	struct r2dp_nh_req q = { .ip = ip, .mac = m };

	if (rte_ring_mp_enqueue_elem(t->req, &q, sizeof(q)) == 0)
		return 4;
	__atomic_fetch_add(&t->n_q_drop, 1, __ATOMIC_RELAXED);
	return -1;
}

int
r2dp_nh_learn(struct r2dp_nh_tab *t, uint32_t ip, const uint8_t mac[6])
{
	const struct rte_hash *h = __atomic_load_n(&t->h, __ATOMIC_ACQUIRE);
	uint64_t m = mac_pack(mac);
	void *data;
	int r;

	if (!h)
		return -1;
	/* the common case -- a known peer, same MAC -- touches no lock */
	if (rte_hash_lookup_data(h, &ip, &data) >= 0 &&
	    (uint64_t)(uintptr_t)data == m)
		return 0;
	if (!rte_spinlock_trylock(&t->lock))
		return nh_enqueue(t, ip, m);     /* maintenance holds it */
	r = nh_put(t, ip, m);
	rte_spinlock_unlock(&t->lock);
	return r == -ENOSPC ? nh_enqueue(t, ip, m) : r;
}

int
r2dp_nh_del(struct r2dp_nh_tab *t, uint32_t ip)
{
	int32_t d;
	int ret = 0;

	rte_spinlock_lock(&t->lock);
	d = t->h ? rte_hash_del_key(t->h, &ip) : -ENOENT;
	if (d >= 0) {
		/* LF tables never free on delete: with QSBR the slot is
		 * recycled after a grace period, else there is no
		 * concurrent reader and it is free at once */
		if (!t->rcu)
			rte_hash_free_key_with_position(t->h, d);
		t->n--;
		ret = 1;
	}
	for (uint32_t i = 0; i < t->npend; i++)
		if (t->pend[i].ip == ip) {
			t->pend[i] = t->pend[--t->npend];
			ret = 1;
			break;
		}
	rte_spinlock_unlock(&t->lock);
	return ret;
}

/* Build a table of twice the capacity holding every entry of the current
 * one.  Called with t->lock held; the old table is untouched until the
 * caller publishes.  NULL on failure (old table keeps serving). */
static struct rte_hash *
nh_grow(struct r2dp_nh_tab *t, uint32_t *ncap)
{
	uint32_t cap = t->cap;

	for (int attempt = 0; attempt < 3; attempt++) {
		struct rte_hash *nh;
		const void *k;
		void *data;
		uint32_t next = 0;
		int ok = 1;

		if (cap >= R2DP_NH_MAX_CAP)
			return NULL;
		cap *= 2;
		if (t->inject_grow_fail) {
			t->inject_grow_fail--;
			return NULL;
		}
		nh = nh_create(t, cap);
		if (!nh)
			return NULL;
		while (rte_hash_iterate(t->h, &k, &data, &next) >= 0)
			if (rte_hash_add_key_data(nh, k, data) < 0) {
				ok = 0;  /* bucket collision: go bigger */
				break;
			}
		if (ok) {
			*ncap = cap;
			return nh;
		}
		rte_hash_free(nh);
	}
	return NULL;
}

void
r2dp_nh_maint(struct r2dp_nh_tab *t)
{
	struct r2dp_nh_req q[64];
	struct rte_hash *old = NULL;
	unsigned nq;

	if (!t->h)
		return;
	rte_spinlock_lock(&t->lock);
	/* park the learner's requests (latest MAC per peer wins) */
	while ((nq = rte_ring_sc_dequeue_burst_elem(t->req, q, sizeof(q[0]),
	    RTE_DIM(q), NULL)) != 0)
		for (unsigned j = 0; j < nq; j++) {
			uint32_t i;
			if (t->wanted && !t->wanted(t->wanted_arg, q[j].ip)) {
				t->n_unwanted++;
				continue;
			}
			for (i = 0; i < t->npend && t->pend[i].ip != q[j].ip; i++)
				;
			if (i < t->npend)
				t->pend[i].mac = q[j].mac;
			else if (t->npend < R2DP_NH_PEND_MAX)
				t->pend[t->npend++] = q[j];
			else
				__atomic_fetch_add(&t->n_q_drop, 1,
				    __ATOMIC_RELAXED);
		}
	for (int pass = 0; pass < 2; pass++) {
		if (t->want_grow) {
			uint32_t ncap = 0;
			struct rte_hash *nh = nh_grow(t, &ncap);
			if (nh) {
				old = t->h;
				__atomic_store_n(&t->h, nh, __ATOMIC_RELEASE);
				t->cap = ncap;
				t->want_grow = 0;
				t->n_grow++;
			} else
				t->n_grow_fail++;
		}
		for (uint32_t i = 0; i < t->npend; )
			if (t->wanted && !t->wanted(t->wanted_arg, t->pend[i].ip)) {
				t->n_unwanted++;
				t->pend[i] = t->pend[--t->npend];
			} else if (nh_put(t, t->pend[i].ip, t->pend[i].mac) >= 0)
				t->pend[i] = t->pend[--t->npend];
			else
				i++;
		if (!t->npend || old)
			break;
	}
	rte_spinlock_unlock(&t->lock);
	if (old) {
		/* readers that loaded the old pointer finish with it before
		 * it goes; this thread is not a reader, so it may wait */
		if (t->rcu)
			rte_rcu_qsbr_synchronize(t->rcu, RTE_QSBR_THRID_INVALID);
		rte_hash_free(old);
	}
}

static void *
nh_thread(void *arg)
{
	struct r2dp_nh_tab *t = arg;

	while (__atomic_load_n(&t->thr_run, __ATOMIC_ACQUIRE)) {
		r2dp_nh_maint(t);
		usleep(1000);
	}
	return NULL;
}

int
r2dp_nh_start(struct r2dp_nh_tab *t)
{
	if (t->thr_run)
		return 0;
	t->thr_run = 1;
	if (pthread_create(&t->thr, NULL, nh_thread, t) != 0) {
		t->thr_run = 0;
		return -EAGAIN;
	}
	return 0;
}

void
r2dp_nh_stop(struct r2dp_nh_tab *t)
{
	if (!t->thr_run)
		return;
	__atomic_store_n(&t->thr_run, 0, __ATOMIC_RELEASE);
	pthread_join(t->thr, NULL);
}

int
r2dp_nh_lookup(const struct r2dp_nh_tab *t, uint32_t ip, uint8_t mac[6])
{
	const struct rte_hash *h = __atomic_load_n(&t->h, __ATOMIC_ACQUIRE);
	void *data;

	if (!h || rte_hash_lookup_data(h, &ip, &data) < 0)
		return 0;
	memcpy(mac, &data, 6);
	return 1;
}

uint64_t
r2dp_nh_lookup_bulk(const struct r2dp_nh_tab *t, const uint32_t *ip,
    unsigned n, uint64_t *mac)
{
	const struct rte_hash *h = __atomic_load_n(&t->h, __ATOMIC_ACQUIRE);
	const void *k[RTE_HASH_LOOKUP_BULK_MAX];
	void *data[RTE_HASH_LOOKUP_BULK_MAX];
	uint64_t hit = 0;

	if (!h || !n)
		return 0;
	if (n > RTE_HASH_LOOKUP_BULK_MAX)
		n = RTE_HASH_LOOKUP_BULK_MAX;
	for (unsigned i = 0; i < n; i++)
		k[i] = &ip[i];
	if (rte_hash_lookup_bulk_data(h, k, n, &hit, data) < 0)
		return 0;
	for (unsigned i = 0; i < n; i++)
		mac[i] = (uint64_t)(uintptr_t)data[i];
	return hit;
}
#endif /* R2DP_HAVE_DPDK */
