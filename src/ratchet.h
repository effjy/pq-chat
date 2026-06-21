/*
 * ratchet.h - Double Ratchet for PQ Chat (forward secrecy + post-compromise
 * security).
 *
 * After the PQXDH-style handshake in session.c agrees a 32-byte root key
 * (post-quantum: Kyber-1024 + X448, authenticated by a CPace PAKE), every
 * message is protected by a fresh, single-use message key produced by a
 * Double Ratchet, faithfully following Signal's specification:
 *
 *   - Symmetric-key ratchet: each sending/receiving chain advances a chain key
 *     through a KDF, so every message gets its own key that is deleted right
 *     after use. Compromising the device today does not expose yesterday's
 *     messages -> FORWARD SECRECY.
 *
 *   - Diffie-Hellman ratchet: each side mixes a fresh X448 key pair into the
 *     root key whenever the conversation turns around. A key compromise heals
 *     after one round trip of new DH material -> POST-COMPROMISE SECURITY.
 *
 * The DH ratchet here is classical X448; the post-quantum guarantee comes from
 * the hybrid KEM that seeds the root key, so a "harvest now, decrypt later"
 * attacker who records the whole session cannot reconstruct it without breaking
 * BOTH Kyber-1024 and X448. See the README for the exact security model.
 *
 * The state holds long-term-ish secrets and must live in locked memory
 * (sodium_mlock) for the duration of a session.
 */
#ifndef PQCHAT_RATCHET_H
#define PQCHAT_RATCHET_H

#include <stddef.h>
#include <stdint.h>

/* Wire sizes. The message header is sent in clear but bound into every
 * message's AEAD associated data, so tampering with it fails authentication. */
#define RATCHET_DH_LEN      56                       /* X448 public key        */
#define RATCHET_HEADER_LEN  (RATCHET_DH_LEN + 4 + 4) /* dh || PN(u32) || N(u32)*/
#define RATCHET_MK_LEN      32                       /* AEAD message key        */
#define RATCHET_NONCE_LEN   24                       /* XChaCha20 nonce         */

/* AEAD authentication-tag overhead added to each ciphertext. */
#define RATCHET_TAG_LEN     16

/* Out-of-order tolerance. Over a single in-order TCP stream skipping is rare,
 * but the bounds defend against a peer that claims an enormous gap. */
#define RATCHET_MAX_SKIP    256
#define RATCHET_SKIP_STORE  512

typedef struct {
    uint8_t  dhr[RATCHET_DH_LEN];   /* the ratchet pubkey this key belongs to */
    uint32_t n;                     /* message number within that chain        */
    uint8_t  mk[RATCHET_MK_LEN];
    uint8_t  nonce[RATCHET_NONCE_LEN];
    int      used;
} ratchet_skipped;

typedef struct {
    uint8_t  rk[32];                            /* root key                    */
    uint8_t  cks[32];  int have_cks;            /* sending chain key           */
    uint8_t  ckr[32];  int have_ckr;            /* receiving chain key         */
    uint8_t  dhs_pub[RATCHET_DH_LEN];           /* our current ratchet keypair */
    uint8_t  dhs_priv[RATCHET_DH_LEN];
    uint8_t  dhr[RATCHET_DH_LEN];  int have_dhr;/* peer's ratchet public key   */
    uint32_t ns, nr, pn;                        /* send/recv/previous counters */
    ratchet_skipped skipped[RATCHET_SKIP_STORE];
    size_t   n_skipped;
} ratchet_state;

/* Generate a fresh X448 ratchet key pair. The listener generates one before
 * the handshake and advertises its public key; both ends feed it into init. */
int ratchet_gen_keypair(uint8_t pub[RATCHET_DH_LEN], uint8_t priv[RATCHET_DH_LEN]);

/* Initialise the side that sends first (the connector / "Alice"). It already
 * knows the peer's initial ratchet public key. */
int ratchet_init_alice(ratchet_state *st, const uint8_t root_key[32],
                       const uint8_t peer_dh_pub[RATCHET_DH_LEN]);

/* Initialise the side that receives first (the listener / "Bob"), supplying
 * the ratchet key pair whose public half it advertised in the handshake. */
int ratchet_init_bob(ratchet_state *st, const uint8_t root_key[32],
                     const uint8_t dhs_pub[RATCHET_DH_LEN],
                     const uint8_t dhs_priv[RATCHET_DH_LEN]);

/* Encrypt one message. Fills header (RATCHET_HEADER_LEN bytes) and ct
 * (ptlen + RATCHET_TAG_LEN bytes); *ctlen receives the ciphertext length.
 * Returns 0 on success, -1 on failure. */
int ratchet_encrypt(ratchet_state *st, const uint8_t *pt, size_t ptlen,
                    uint8_t header[RATCHET_HEADER_LEN],
                    uint8_t *ct, size_t *ctlen);

/* Decrypt one message into pt (must hold at least ctlen bytes); *ptlen
 * receives the plaintext length. Performs DH-ratchet steps and skipped-key
 * handling as required. Returns 0 on success, -1 on failure (tampered,
 * wrong key, or an out-of-bounds skip request). */
int ratchet_decrypt(ratchet_state *st, const uint8_t header[RATCHET_HEADER_LEN],
                    const uint8_t *ct, size_t ctlen,
                    uint8_t *pt, size_t *ptlen);

/* Zero all secret state. */
void ratchet_wipe(ratchet_state *st);

#endif /* PQCHAT_RATCHET_H */
