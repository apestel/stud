/*
 * shctx.c
 *
 * Copyright (C) 2011 EXCELIANCE 
 * 
 * Author: Emeric Brun - emeric@exceliance.fr
 *
 */
#include <sys/mman.h>
#ifdef USE_SYSCALL_FUTEX
#include <unistd.h>
#include <linux/futex.h>  
#include <sys/syscall.h>
#else /* USE_SYSCALL_FUTEX */
#include <pthread.h>
#endif /* USE_SYSCALL_FUTEX */

#include "ebtree/ebmbtree.h"
#include "shctx.h"

#ifndef SHSESS_MAX_DATA_LEN
#define SHSESS_MAX_DATA_LEN 512
#endif

struct shared_session {
        struct ebmb_node key;
        unsigned char key_data[SSL_MAX_SSL_SESSION_ID_LENGTH];
        int data_len;
        unsigned char data[SHSESS_MAX_DATA_LEN];
        struct shared_session *p;
        struct shared_session *n;
};


struct shared_context {
#ifdef USE_SYSCALL_FUTEX
        unsigned int waiters;
#else /* USE_SYSCALL_FUTEX */
        pthread_mutex_t mutex;
#endif
        struct shared_session active;
        struct shared_session free;
};

/* Static shared context */
static struct shared_context *shctx = NULL;


/* Lock functions */
#ifdef USE_SYSCALL_FUTEX
static inline unsigned int xchg(unsigned int *ptr, unsigned int x)
{
	__asm volatile("lock xchgl %0,%1"
		     : "=r" (x), "+m" (*ptr)
		     : "0" (x)
		     : "memory");
	return x;
}

static inline unsigned int cmpxchg(unsigned int *ptr, unsigned int old, unsigned int new)
{
	unsigned int ret;

	__asm volatile("lock cmpxchgl %2,%1"
		     : "=a" (ret), "+m" (*ptr)
		     : "r" (new), "0" (old)
		     : "memory");
	return ret;
}

static inline unsigned char atomic_inc(unsigned int *ptr)
{
	unsigned char ret;
	__asm volatile("lock incl %0\n"
		     "setne %1\n"
		     : "+m" (*ptr), "=qm" (ret)
		     :
		     : "memory");
	return ret;
}

static inline unsigned char atomic_dec(unsigned int *ptr)
{
	unsigned char ret;
	__asm volatile("lock decl %0\n"
		     "setne %1\n"
		     : "+m" (*ptr), "=qm" (ret)
		     :
		     : "memory");
	return ret;
}

static inline void shared_context_lock(void)
{
	unsigned int x;

	x = cmpxchg(&shctx->waiters, 0, 1);
	if (x) {
		if (x != 2)
			x = xchg(&shctx->waiters, 2);

		while (x) {
			syscall(SYS_futex, &shctx->waiters, FUTEX_WAIT, 2, NULL, 0, 0);
			x = xchg(&shctx->waiters, 2);
		}
	}
}

static inline void shared_context_unlock(void)
{
	if (atomic_dec(&shctx->waiters)) {
		shctx->waiters = 0;
		syscall(SYS_futex, &shctx->waiters, FUTEX_WAKE, 1, NULL, 0, 0);
	}
}

#else /* USE_SYSCALL_FUTEX */

#define shared_context_lock(v) pthread_mutex_lock(&shctx->mutex)
#define shared_context_unlock(v) pthread_mutex_unlock(&shctx->mutex)

#endif

/* List Macros */

#define shsess_unset(s)		(s)->n->p = (s)->p; \
				(s)->p->n = (s)->n;

#define shsess_set_free(s)	shsess_unset(s) \
				(s)->p = &shctx->free; \
				(s)->n = shctx->free.n; \
				shctx->free.n->p = s; \
				shctx->free.n = s;


#define shsess_set_active(s)	shsess_unset(s) \
				(s)->p = &shctx->active; \
				(s)->n = shctx->active.n; \
				shctx->active.n->p = s; \
				shctx->active.n = s;


#define shsess_get_next()	(shctx->free.p == shctx->free.n) ? \
					shctx->active.p : shctx->free.p;

/* Tree Macros */

#define shsess_tree_delete(s)	ebmb_delete(&(s)->key);

#define shsess_tree_insert(s)	(struct shared_session *)ebmb_insert(&shctx->active.key.node.branches, \
							     &(s)->key, SSL_MAX_SSL_SESSION_ID_LENGTH);

#define shsess_tree_lookup(k)	(struct shared_session *)ebmb_lookup(&shctx->active.key.node.branches, \
							(k), SSL_MAX_SSL_SESSION_ID_LENGTH);

/* Other Macros */

#define shsess_set_key(s,k,l)	{ memcpy((s)->key_data, (k), (l)); \
					if ((l) < SSL_MAX_SSL_SESSION_ID_LENGTH) \
						memset((s)->key_data+(l), 0, SSL_MAX_SSL_SESSION_ID_LENGTH-(l)); }; 


/* SSL context callbacks */

/* SSL callback used on new session creation */
int shctx_new_cb(SSL *ssl, SSL_SESSION *sess) {
	(void)ssl;
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN],*p;
	unsigned int data_len;

	/* check if session reserved size in aligned buffer is large enougth for the ASN1 encode session */
	data_len=i2d_SSL_SESSION(sess, NULL);
	if(data_len > SHSESS_MAX_DATA_LEN)
		return 1;

	/* process ASN1 session encoding before the lock: lower cost */
	p = data;
	i2d_SSL_SESSION(sess, &p);

	shared_context_lock();
    
	shsess = shsess_get_next();

	shsess_tree_delete(shsess);

	shsess_set_key(shsess, sess->session_id, sess->session_id_length);

	/* it returns the already existing node or current node if none, never returns null */
	shsess = shsess_tree_insert(shsess);

	/* store ASN1 encoded session into cache */
	shsess->data_len = data_len;
	memcpy(shsess->data, data, data_len);
    
	shsess_set_active(shsess);

	shared_context_unlock();

	return 1; /* leave the session in local cache for reuse */
}

/* SSL callback used on lookup an existing session cause none found in internal cache */
SSL_SESSION *shctx_get_cb(SSL *ssl, unsigned char *key, int key_len, int *do_copy) {
	(void)ssl;
	struct shared_session *shsess;
	unsigned char data[SHSESS_MAX_DATA_LEN], *p;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned int data_len;
	SSL_SESSION *sess;

        /* allow the session to be freed automatically by openssl */
	*do_copy = 0;

	/* tree key is zeros padded sessionid */
	if ( key_len < SSL_MAX_SSL_SESSION_ID_LENGTH ) {
		memcpy(tmpkey, key, key_len);
		memset(tmpkey+key_len, 0, SSL_MAX_SSL_SESSION_ID_LENGTH-key_len); 
		key = tmpkey;
	}

        /* lock cache */
	shared_context_lock();

	/* lookup for session */
	shsess = shsess_tree_lookup(key);
	if(!shsess) {
		/* no session found: unlock cache and exit */
		shared_context_unlock();
		return NULL;
	}

	/* copy ASN1 session data to decode outside the lock */
	data_len = shsess->data_len;
	memcpy(data, shsess->data, shsess->data_len);

	shsess_set_active(shsess);

	shared_context_unlock();

	/* decode ASN1 session */
        p = data;
	sess = d2i_SSL_SESSION(NULL, (const unsigned char **)&p, data_len);

	return sess;
}

/* SSL callback used to signal session is no more used in internal cache */
void shctx_remove_cb(SSL_CTX *ctx, SSL_SESSION *sess) {
	(void)ctx;
	struct shared_session *shsess;
	unsigned char tmpkey[SSL_MAX_SSL_SESSION_ID_LENGTH];
	unsigned char *key = sess->session_id;

	/* tree key is zeros padded sessionid */
	if ( sess->session_id_length < SSL_MAX_SSL_SESSION_ID_LENGTH ) {
		memcpy(tmpkey, sess->session_id, sess->session_id_length);
		memset(tmpkey+sess->session_id_length, 0, SSL_MAX_SSL_SESSION_ID_LENGTH-sess->session_id_length); 
		key = tmpkey;
	}

	shared_context_lock();

	/* lookup for session */
	shsess = shsess_tree_lookup(key);
        if ( shsess )  {
		shsess_set_free(shsess);
	}

	/* unlock cache */
	shared_context_unlock();
}

/* Init shared memory context if not allocated and set SSL context callbacks
 * size is the max number of stored session 
 * Returns: -1 on alloc failure, size if performs context alloc, and 0 if just perform
 * callbacks registration */
int shared_context_init(SSL_CTX *ctx, int size)
{
	int ret = 0;

	if (!shctx) {
		int i;

#ifndef USE_SYSCALL_FUTEX
		pthread_mutexattr_t attr;
#endif /* USE_SYSCALL_FUTEX */
		struct shared_session *prev,*cur;

		shctx = (struct shared_context *)mmap(NULL, sizeof(struct shared_context)+(size*sizeof(struct shared_session)),
								PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
		if (!shctx)
			return -1;

#ifdef USE_SYSCALL_FUTEX
		shctx->waiters = 0;
#else
		pthread_mutexattr_init(&attr);
		pthread_mutexattr_setpshared(&attr, PTHREAD_PROCESS_SHARED);
		pthread_mutex_init(&shctx->mutex, &attr);
#endif
		memset(&shctx->active.key, 0, sizeof(struct ebmb_node));
		memset(&shctx->free.key, 0, sizeof(struct ebmb_node));

		/* No duplicate authorized in tree: */
		shctx->active.key.node.branches.b[1] = (void *)1;

		cur = &shctx->active; 
		cur->n = cur->p = cur;
		
		cur = &shctx->free;
		for ( i = 0 ; i < size ; i++) {
			prev = cur;
			cur = (struct shared_session *)((char *)prev + sizeof(struct shared_session));
			prev->n = cur;
			cur->p = prev;
		}
		cur->n = &shctx->free;
		shctx->free.p = cur;

		ret = size;
	}

	/* set SSL internal cache size to external cache / 8  + 123 */
	SSL_CTX_sess_set_cache_size(ctx, size >> 3 | 0x3ff);

	/* Set callbacks */
	SSL_CTX_sess_set_new_cb(ctx, shctx_new_cb);
	SSL_CTX_sess_set_get_cb(ctx, shctx_get_cb);
	SSL_CTX_sess_set_remove_cb(ctx, shctx_remove_cb);

	return ret;
}

