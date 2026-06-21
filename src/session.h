/*
 * session.h - PQ Chat secure session: handshake + framed messaging.
 *
 * Topology mirrors PQ Transfer: one peer listens on a port, the other connects
 * to it; after that the link is symmetric and either side may speak.
 *
 * Handshake (PQXDH-style, all sizes from hybrid_kem.h / ratchet.h):
 *
 *   listener -> connector  MAGIC | sid(16) | CPace Yb(32)
 *                                | hybrid_pk(HK_PK_LEN) | ratchet_pub(56)
 *   connector -> listener  MAGIC | CPace Ya(32) | kem_ct(HK_KEM_CT_LEN)
 *
 * The listener generates a fresh hybrid KEM keypair AND an initial X448 ratchet
 * keypair, advertising both public keys. The connector encapsulates to the KEM
 * key (Kyber-1024 + X448 -> 32-byte secret) and runs CPace over the optional
 * passphrase. Both sides fold the KEM secret and the CPace key into one 32-byte
 * root key, which seeds the Double Ratchet (ratchet.c). The connector then
 * sends one zero-length "priming" message so the listener gains its first
 * sending chain and the channel becomes fully bidirectional.
 *
 * Each subsequent message on the wire is:  header(64) | u32 ctlen | ct(ctlen).
 */
#ifndef PQCHAT_SESSION_H
#define PQCHAT_SESSION_H

#include <stddef.h>
#include <stdint.h>

#define PQC_PASS_MAX     4096
#define PQC_MSG_MAX      65536   /* max plaintext bytes per chat message */

/* Connection parameters. */
typedef struct {
    int      listen;                 /* 1 = listen/host, 0 = connect/join */
    char     host[256];              /* connect: peer host; listen: bind addr */
    uint16_t port;
    char     passphrase[PQC_PASS_MAX];
} pqc_config;

/* An established secure channel. Opaque; created by pqc_connect. */
typedef struct pqc_chan pqc_chan;

/* Perform the handshake described above. On success allocates *out and returns
 * 0; on failure returns -1 with a message in err. *cancel, if non-NULL, is
 * polled to abort a blocking wait (listen/accept/connect). */
int pqc_connect(const pqc_config *cfg, pqc_chan **out, volatile int *cancel,
                char *err, size_t errlen);

/* Receive and decrypt one message. text (size textcap) receives a
 * NUL-terminated UTF-8 string; *is_chat is 1 for a user message, 0 for an
 * internal control message (e.g. the priming message) that should not be
 * displayed. Returns 0 on success, -1 on error/disconnect (message in err),
 * 1 if cancelled. */
int pqc_recv(pqc_chan *c, char *text, size_t textcap, int *is_chat,
             volatile int *cancel, char *err, size_t errlen);

/* Encrypt and send one chat message. Thread-safe against a concurrent
 * pqc_recv (the ratchet and socket writes are mutex-guarded). Returns 0 on
 * success, -1 on failure with a message in err. */
int pqc_send(pqc_chan *c, const char *text, char *err, size_t errlen);

/* Close the socket and wipe all secret state. */
void pqc_close(pqc_chan *c);

#endif /* PQCHAT_SESSION_H */
