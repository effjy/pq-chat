/*
 * session.c - PQ Chat secure session engine (see session.h).
 *
 * Reuses the hybrid KEM (hybrid_kem.c), the CPace PAKE (cpace.c) and the
 * Double Ratchet (ratchet.c). Networking is blocking TCP made cancel-aware by
 * driving every socket wait through poll() in short slices, exactly as in
 * PQ Transfer. After the handshake, the ratchet state and all socket writes
 * are guarded by a mutex so a sending GUI thread and a receiving worker thread
 * can share one channel safely.
 */
#include "session.h"
#include "hybrid_kem.h"
#include "cpace.h"
#include "ratchet.h"

#include <sodium.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SALT_LEN   16
#define MAGIC_LEN  8

/* Protocol magic + version. Bump the trailing byte on any wire change. */
static const uint8_t PQCMAGIC[MAGIC_LEN] = { 'P','Q','C','H','A','T', 0x01, 0x00 };

/* Plaintext message types (first byte of every ratchet plaintext). */
#define MSG_CONTROL  0   /* internal (e.g. the priming message); not shown */
#define MSG_CHAT     1   /* a user chat line                                */

#define CT_MAX  (PQC_MSG_MAX + 1 + RATCHET_TAG_LEN)
#define PT_MAX  (PQC_MSG_MAX + 1)

/* IO results. */
#define IO_OK      0
#define IO_ERR    -1
#define IO_CANCEL -2

struct pqc_chan {
    int             fd;
    int             listener;       /* 1 = we are "Bob" (received first)     */
    ratchet_state   rt;
    pthread_mutex_t mtx;            /* guards rt and socket writes            */
};

/* ----- little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

static void seterr(char *err, size_t errlen, const char *msg) {
    if (err && errlen) snprintf(err, errlen, "%s", msg);
}

/* ----- cancel-aware socket IO ------------------------------------------ */

static int set_nonblocking(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    return (fl < 0) ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static int wait_io(int fd, short events, volatile int *cancel) {
    struct pollfd pfd = { fd, events, 0 };
    for (;;) {
        if (cancel && *cancel) return IO_CANCEL;
        int r = poll(&pfd, 1, 200);
        if (r < 0) { if (errno == EINTR) continue; return IO_ERR; }
        if (r == 0) continue;
        if (pfd.revents & (POLLERR | POLLNVAL)) return IO_ERR;
        return IO_OK;
    }
}

static int io_read_all(int fd, void *buf, size_t n, volatile int *cancel) {
    uint8_t *p = buf; size_t off = 0;
    while (off < n) {
        int w = wait_io(fd, POLLIN, cancel);
        if (w != IO_OK) return w;
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r == 0) return IO_ERR;                 /* peer closed */
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return IO_ERR;
        }
        off += (size_t)r;
    }
    return IO_OK;
}

static int io_write_all(int fd, const void *buf, size_t n, volatile int *cancel) {
    const uint8_t *p = buf; size_t off = 0;
    while (off < n) {
        int w = wait_io(fd, POLLOUT, cancel);
        if (w != IO_OK) return w;
        ssize_t r = send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return IO_ERR;
        }
        off += (size_t)r;
    }
    return IO_OK;
}

/* ----- listener / connector (same as PQ Transfer) ---------------------- */

static int make_listener(const char *bind_addr, uint16_t port,
                         char *err, size_t errlen) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    const char *node = (bind_addr && *bind_addr) ? bind_addr : NULL;
    if (getaddrinfo(node, portstr, &hints, &res) != 0 || !res) {
        seterr(err, errlen, "Invalid bind address."); return -1;
    }
    int fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        if (node == NULL && rp->ai_family != AF_INET6 && res->ai_next) continue;
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;
        int yes = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
        if (rp->ai_family == AF_INET6) {
            int off = 0;
            setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
        }
        if (bind(fd, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(fd); fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0) { seterr(err, errlen, "Could not bind to the port (already in use?)."); return -1; }
    if (listen(fd, 1) != 0 || set_nonblocking(fd) != 0) {
        seterr(err, errlen, "Socket setup failed."); close(fd); return -1;
    }
    return fd;
}

static int accept_one(int lfd, volatile int *cancel, char *err, size_t errlen) {
    for (;;) {
        int w = wait_io(lfd, POLLIN, cancel);
        if (w == IO_CANCEL) { seterr(err, errlen, "Cancelled."); return -1; }
        if (w != IO_OK)     { seterr(err, errlen, "Accept failed."); return -1; }
        int cfd = accept(lfd, NULL, NULL);
        if (cfd >= 0) return cfd;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == ECONNABORTED ||
            errno == EINTR) continue;
        seterr(err, errlen, "Accept failed."); return -1;
    }
}

static int connect_one(struct addrinfo *rp, volatile int *cancel, int *cancelled) {
    int fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (fd < 0) return -1;
    if (set_nonblocking(fd) != 0) { close(fd); return -1; }
    int rc = connect(fd, rp->ai_addr, rp->ai_addrlen);
    if (rc == 0) return fd;
    if (errno != EINPROGRESS) { close(fd); return -1; }
    int waited = 0;
    while (waited < 15000) {
        if (cancel && *cancel) { *cancelled = 1; close(fd); return -1; }
        struct pollfd pfd = { fd, POLLOUT, 0 };
        int r = poll(&pfd, 1, 200);
        if (r < 0) { if (errno == EINTR) continue; break; }
        if (r == 0) { waited += 200; continue; }
        int soerr = 0; socklen_t sl = sizeof(soerr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr == 0) return fd;
        break;
    }
    close(fd);
    return -1;
}

static int connect_to(const char *host, uint16_t port, volatile int *cancel,
                      char *err, size_t errlen) {
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%u", (unsigned)port);
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, portstr, &hints, &res) != 0 || !res) {
        seterr(err, errlen, "Could not resolve the host."); return -1;
    }
    int cancelled = 0, fd = -1;
    for (rp = res; rp; rp = rp->ai_next) {
        fd = connect_one(rp, cancel, &cancelled);
        if (fd >= 0 || cancelled) break;
    }
    freeaddrinfo(res);
    if (fd < 0)
        seterr(err, errlen, cancelled ? "Cancelled."
                                      : "Could not connect to the host (timed out?).");
    return fd;
}

/* ----- root key -------------------------------------------------------- *
 * Fold the post-quantum KEM secret and the CPace PAKE key into one 32-byte
 * root key for the ratchet. Secret if EITHER the hybrid KEM holds (post-quantum
 * confidentiality vs any passive attacker) OR the passphrase is unknown to an
 * active attacker (CPace authentication, no offline dictionary attack). */
static void derive_root_key(uint8_t key[32], const uint8_t isk[CPACE_ISK_LEN],
                            const uint8_t kem_shared[32],
                            const uint8_t Ya[CPACE_MSG_LEN],
                            const uint8_t Yb[CPACE_MSG_LEN]) {
    crypto_generichash_state h;
    crypto_generichash_init(&h, isk, CPACE_ISK_LEN, 32);
    crypto_generichash_update(&h, (const uint8_t *)"PQChat-root-v1", 14);
    crypto_generichash_update(&h, kem_shared, 32);
    crypto_generichash_update(&h, Ya, CPACE_MSG_LEN);
    crypto_generichash_update(&h, Yb, CPACE_MSG_LEN);
    crypto_generichash_final(&h, key, 32);
}

/* Allocate a channel and lock its secret state into RAM. */
static pqc_chan *chan_new(int fd, int listener) {
    pqc_chan *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd = fd;
    c->listener = listener;
    if (pthread_mutex_init(&c->mtx, NULL) != 0) { free(c); return NULL; }
    sodium_mlock(&c->rt, sizeof(c->rt));
    return c;
}

/* Send one already-typed plaintext (type byte prepended) as a ratchet frame.
 * Caller must hold c->mtx. Wire frame: header(64) | u32 ctlen | ct. */
static int send_typed_locked(pqc_chan *c, uint8_t type,
                             const char *data, size_t len, char *err, size_t errlen) {
    if (len > PQC_MSG_MAX) { seterr(err, errlen, "Message too long."); return -1; }
    uint8_t pt[PT_MAX];
    pt[0] = type;
    if (len) memcpy(pt + 1, data, len);

    uint8_t header[RATCHET_HEADER_LEN];
    uint8_t ct[CT_MAX];
    size_t ctlen = 0;
    if (ratchet_encrypt(&c->rt, pt, len + 1, header, ct, &ctlen) != 0) {
        sodium_memzero(pt, sizeof(pt));
        seterr(err, errlen, "Encryption failed."); return -1;
    }
    sodium_memzero(pt, sizeof(pt));

    uint8_t lenbuf[4];
    put_u32(lenbuf, (uint32_t)ctlen);
    if (io_write_all(c->fd, header, sizeof(header), NULL) != IO_OK ||
        io_write_all(c->fd, lenbuf, sizeof(lenbuf), NULL) != IO_OK ||
        io_write_all(c->fd, ct, ctlen, NULL) != IO_OK) {
        seterr(err, errlen, "Send failed (connection lost?)."); return -1;
    }
    return 0;
}

/* ----- public: handshake ----------------------------------------------- */

int pqc_connect(const pqc_config *cfg, pqc_chan **out, volatile int *cancel,
                char *err, size_t errlen) {
    int ret = -1, lfd = -1, fd = -1;
    pqc_chan *c = NULL;

    /* Secret material, pinned in locked memory. */
    uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES], x448_pk[HK_X448_PUBKEY_LEN];
    uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES], x448_sk[HK_X448_PRIVKEY_LEN];
    uint8_t rat_pub[RATCHET_DH_LEN], rat_priv[RATCHET_DH_LEN];
    uint8_t sid[SALT_LEN];
    uint8_t Ya[CPACE_MSG_LEN], Yb[CPACE_MSG_LEN], isk[CPACE_ISK_LEN];
    uint8_t shared[32], root[32];
    cpace_state cp;
    sodium_mlock(kyber_sk, sizeof(kyber_sk));
    sodium_mlock(x448_sk, sizeof(x448_sk));
    sodium_mlock(rat_priv, sizeof(rat_priv));
    sodium_mlock(shared, sizeof(shared));
    sodium_mlock(root, sizeof(root));
    sodium_mlock(isk, sizeof(isk));
    sodium_mlock(&cp, sizeof(cp));

    if (cfg->listen) {
        /* ---- Listener (Bob): advertise KEM + ratchet public keys. ---- */
        if (hk_generate_keypair(kyber_pk, kyber_sk, x448_pk, x448_sk) != 0) {
            seterr(err, errlen, "Key generation failed."); goto done;
        }
        if (ratchet_gen_keypair(rat_pub, rat_priv) != 0) {
            seterr(err, errlen, "Key generation failed."); goto done;
        }
        randombytes_buf(sid, sizeof(sid));
        if (cpace_start(&cp, Yb, cfg->passphrase, sid, sizeof(sid)) != 0) {
            seterr(err, errlen, "PAKE setup failed."); goto done;
        }

        lfd = make_listener(cfg->host, cfg->port, err, errlen);
        if (lfd < 0) goto done;
        fd = accept_one(lfd, cancel, err, errlen);
        if (fd < 0) goto done;
        if (set_nonblocking(fd) != 0) { seterr(err, errlen, "Socket setup failed."); goto done; }
        int yes = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

        /* HELLO: MAGIC | sid | Yb | kyber_pk | x448_pk | ratchet_pub. */
        uint8_t hello[MAGIC_LEN + SALT_LEN + CPACE_MSG_LEN +
                      HK_KYBER_PUBLICKEYBYTES + HK_X448_PUBKEY_LEN + RATCHET_DH_LEN];
        uint8_t *p = hello;
        memcpy(p, PQCMAGIC, MAGIC_LEN);                 p += MAGIC_LEN;
        memcpy(p, sid, SALT_LEN);                       p += SALT_LEN;
        memcpy(p, Yb, CPACE_MSG_LEN);                   p += CPACE_MSG_LEN;
        memcpy(p, kyber_pk, HK_KYBER_PUBLICKEYBYTES);   p += HK_KYBER_PUBLICKEYBYTES;
        memcpy(p, x448_pk, HK_X448_PUBKEY_LEN);         p += HK_X448_PUBKEY_LEN;
        memcpy(p, rat_pub, RATCHET_DH_LEN);
        if (io_write_all(fd, hello, sizeof(hello), cancel) != IO_OK) {
            seterr(err, errlen, "Handshake send failed."); goto done;
        }

        /* Response: MAGIC | Ya | kem_ct. */
        uint8_t rmagic[MAGIC_LEN], kem_ct[HK_KEM_CT_LEN];
        if (io_read_all(fd, rmagic, MAGIC_LEN, cancel) != IO_OK) {
            seterr(err, errlen, "Handshake receive failed."); goto done;
        }
        if (memcmp(rmagic, PQCMAGIC, MAGIC_LEN) != 0) {
            seterr(err, errlen, "Peer is not PQ Chat (or version mismatch)."); goto done;
        }
        if (io_read_all(fd, Ya, CPACE_MSG_LEN, cancel) != IO_OK ||
            io_read_all(fd, kem_ct, HK_KEM_CT_LEN, cancel) != IO_OK) {
            seterr(err, errlen, "Handshake receive failed."); goto done;
        }
        if (hk_decapsulate(shared, kem_ct, kyber_sk, x448_sk) != 0) {
            seterr(err, errlen, "Key agreement failed."); goto done;
        }
        if (cpace_finish(isk, &cp, Ya, Ya, Yb, sid, sizeof(sid)) != 0) {
            seterr(err, errlen, "PAKE failed (invalid peer message)."); goto done;
        }
        derive_root_key(root, isk, shared, Ya, Yb);

        c = chan_new(fd, 1);
        if (!c) { seterr(err, errlen, "Out of memory."); goto done; }
        if (ratchet_init_bob(&c->rt, root, rat_pub, rat_priv) != 0) {
            seterr(err, errlen, "Ratchet init failed."); pqc_close(c); c = NULL; goto done;
        }
        fd = -1;                 /* ownership moved into the channel */
    } else {
        /* ---- Connector (Alice): encapsulate, then prime the channel. ---- */
        fd = connect_to(cfg->host, cfg->port, cancel, err, errlen);
        if (fd < 0) goto done;
        int yes = 1; setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
        if (set_nonblocking(fd) != 0) { seterr(err, errlen, "Socket setup failed."); goto done; }

        /* Read HELLO. */
        uint8_t hmagic[MAGIC_LEN];
        if (io_read_all(fd, hmagic, MAGIC_LEN, cancel) != IO_OK) {
            seterr(err, errlen, "Handshake receive failed."); goto done;
        }
        if (memcmp(hmagic, PQCMAGIC, MAGIC_LEN) != 0) {
            seterr(err, errlen, "Peer is not PQ Chat (or version mismatch)."); goto done;
        }
        if (io_read_all(fd, sid, SALT_LEN, cancel) != IO_OK ||
            io_read_all(fd, Yb, CPACE_MSG_LEN, cancel) != IO_OK ||
            io_read_all(fd, kyber_pk, HK_KYBER_PUBLICKEYBYTES, cancel) != IO_OK ||
            io_read_all(fd, x448_pk, HK_X448_PUBKEY_LEN, cancel) != IO_OK ||
            io_read_all(fd, rat_pub, RATCHET_DH_LEN, cancel) != IO_OK) {
            seterr(err, errlen, "Handshake receive failed."); goto done;
        }

        uint8_t kem_ct[HK_KEM_CT_LEN];
        if (hk_encapsulate(shared, kem_ct, kyber_pk, x448_pk) != 0) {
            seterr(err, errlen, "Key agreement failed."); goto done;
        }
        if (cpace_start(&cp, Ya, cfg->passphrase, sid, sizeof(sid)) != 0) {
            seterr(err, errlen, "PAKE setup failed."); goto done;
        }
        if (cpace_finish(isk, &cp, Yb, Ya, Yb, sid, sizeof(sid)) != 0) {
            seterr(err, errlen, "PAKE failed (invalid peer message)."); goto done;
        }
        derive_root_key(root, isk, shared, Ya, Yb);

        /* Response: MAGIC | Ya | kem_ct. */
        uint8_t resp[MAGIC_LEN + CPACE_MSG_LEN + HK_KEM_CT_LEN];
        uint8_t *p = resp;
        memcpy(p, PQCMAGIC, MAGIC_LEN);   p += MAGIC_LEN;
        memcpy(p, Ya, CPACE_MSG_LEN);     p += CPACE_MSG_LEN;
        memcpy(p, kem_ct, HK_KEM_CT_LEN);
        if (io_write_all(fd, resp, sizeof(resp), cancel) != IO_OK) {
            seterr(err, errlen, "Handshake send failed."); goto done;
        }

        c = chan_new(fd, 0);
        if (!c) { seterr(err, errlen, "Out of memory."); goto done; }
        if (ratchet_init_alice(&c->rt, root, rat_pub) != 0) {
            seterr(err, errlen, "Ratchet init failed."); pqc_close(c); c = NULL; goto done;
        }
        fd = -1;

        /* Priming message: gives the listener its first sending chain so the
         * channel is immediately bidirectional. Not displayed by the peer. */
        pthread_mutex_lock(&c->mtx);
        int prc = send_typed_locked(c, MSG_CONTROL, NULL, 0, err, errlen);
        pthread_mutex_unlock(&c->mtx);
        if (prc != 0) { pqc_close(c); c = NULL; goto done; }
    }

    *out = c;
    ret = 0;

done:
    if (lfd >= 0) close(lfd);
    if (fd >= 0) close(fd);
    sodium_memzero(rat_pub, sizeof(rat_pub));
    sodium_munlock(kyber_sk, sizeof(kyber_sk));
    sodium_munlock(x448_sk, sizeof(x448_sk));
    sodium_munlock(rat_priv, sizeof(rat_priv));
    sodium_munlock(shared, sizeof(shared));
    sodium_munlock(root, sizeof(root));
    sodium_munlock(isk, sizeof(isk));
    sodium_munlock(&cp, sizeof(cp));
    return ret;
}

/* ----- public: send / receive ------------------------------------------ */

int pqc_send(pqc_chan *c, const char *text, char *err, size_t errlen) {
    if (!c || !text) { seterr(err, errlen, "Not connected."); return -1; }
    size_t len = strlen(text);
    pthread_mutex_lock(&c->mtx);
    int rc = send_typed_locked(c, MSG_CHAT, text, len, err, errlen);
    pthread_mutex_unlock(&c->mtx);
    return rc;
}

int pqc_recv(pqc_chan *c, char *text, size_t textcap, int *is_chat,
             volatile int *cancel, char *err, size_t errlen) {
    if (is_chat) *is_chat = 0;

    uint8_t header[RATCHET_HEADER_LEN];
    int w = io_read_all(c->fd, header, sizeof(header), cancel);
    if (w == IO_CANCEL) return 1;
    if (w != IO_OK) { seterr(err, errlen, "Peer disconnected."); return -1; }

    uint8_t lenbuf[4];
    w = io_read_all(c->fd, lenbuf, sizeof(lenbuf), cancel);
    if (w == IO_CANCEL) return 1;
    if (w != IO_OK) { seterr(err, errlen, "Peer disconnected."); return -1; }
    uint32_t ctlen = get_u32(lenbuf);
    if (ctlen < 1 + RATCHET_TAG_LEN || ctlen > CT_MAX) {
        seterr(err, errlen, "Malformed message frame."); return -1;
    }

    uint8_t ct[CT_MAX];
    w = io_read_all(c->fd, ct, ctlen, cancel);
    if (w == IO_CANCEL) return 1;
    if (w != IO_OK) { seterr(err, errlen, "Peer disconnected."); return -1; }

    uint8_t pt[PT_MAX];
    size_t ptlen = 0;
    pthread_mutex_lock(&c->mtx);
    int rc = ratchet_decrypt(&c->rt, header, ct, ctlen, pt, &ptlen);
    pthread_mutex_unlock(&c->mtx);
    if (rc != 0 || ptlen < 1) {
        sodium_memzero(pt, sizeof(pt));
        seterr(err, errlen, "Authentication failed (tampered or wrong passphrase).");
        return -1;
    }

    uint8_t type = pt[0];
    size_t body = ptlen - 1;
    if (type == MSG_CHAT) {
        if (body >= textcap) body = textcap - 1;   /* truncate defensively */
        memcpy(text, pt + 1, body);
        text[body] = '\0';
        if (is_chat) *is_chat = 1;
    } else {
        if (textcap) text[0] = '\0';                /* control: nothing to show */
    }
    sodium_memzero(pt, sizeof(pt));
    return 0;
}

void pqc_close(pqc_chan *c) {
    if (!c) return;
    if (c->fd >= 0) close(c->fd);
    ratchet_wipe(&c->rt);
    sodium_munlock(&c->rt, sizeof(c->rt));
    pthread_mutex_destroy(&c->mtx);
    free(c);
}
