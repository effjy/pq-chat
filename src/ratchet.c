/*
 * ratchet.c - Double Ratchet implementation (see ratchet.h).
 *
 * Closely follows the algorithm in Signal's "The Double Ratchet Algorithm"
 * specification (Perrin & Marlinspike), instantiated with:
 *   - X448 for the DH ratchet            (hk_x448_keypair / hk_x448_dh)
 *   - BLAKE2b (libsodium crypto_generichash) for KDF_RK and KDF_CK
 *   - XChaCha20-Poly1305 for the authenticated message encryption
 *
 * Every secret (root key, chain keys, message keys) is derived, used once and
 * overwritten; the per-message header is bound as AEAD associated data.
 */
#include "ratchet.h"
#include "hybrid_kem.h"

#include <sodium.h>
#include <string.h>

/* ----- little-endian helpers ------------------------------------------- */

static void put_u32(uint8_t *b, uint32_t v) {
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff;
    b[2] = (v >> 16) & 0xff; b[3] = (v >> 24) & 0xff;
}
static uint32_t get_u32(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
           ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}

/* ----- KDFs ------------------------------------------------------------- *
 * KDF_RK: (rk, dh) -> (rk', ck). BLAKE2b keyed by the current root key over a
 * domain string and the DH output, split into the next root key and a chain
 * key. KDF_CK: ck -> (ck', mk, nonce). The chain key is advanced with a "0x02"
 * constant; the one-time message key + nonce come from a "0x01" constant. */

static void kdf_rk(const uint8_t rk[32], const uint8_t dh[RATCHET_DH_LEN],
                   uint8_t rk_out[32], uint8_t ck_out[32]) {
    uint8_t out[64];
    crypto_generichash_state h;
    crypto_generichash_init(&h, rk, 32, sizeof(out));
    crypto_generichash_update(&h, (const uint8_t *)"PQChat-Ratchet-RK-v1", 20);
    crypto_generichash_update(&h, dh, RATCHET_DH_LEN);
    crypto_generichash_final(&h, out, sizeof(out));
    memcpy(rk_out, out, 32);
    memcpy(ck_out, out + 32, 32);
    sodium_memzero(out, sizeof(out));
}

static void kdf_ck(const uint8_t ck[32], uint8_t ck_out[32],
                   uint8_t mk[RATCHET_MK_LEN], uint8_t nonce[RATCHET_NONCE_LEN]) {
    const uint8_t c_ck[1] = { 0x02 };
    const uint8_t c_mk[1] = { 0x01 };
    uint8_t mkmat[RATCHET_MK_LEN + RATCHET_NONCE_LEN];
    crypto_generichash(ck_out, 32, c_ck, sizeof(c_ck), ck, 32);
    crypto_generichash(mkmat, sizeof(mkmat), c_mk, sizeof(c_mk), ck, 32);
    memcpy(mk, mkmat, RATCHET_MK_LEN);
    memcpy(nonce, mkmat + RATCHET_MK_LEN, RATCHET_NONCE_LEN);
    sodium_memzero(mkmat, sizeof(mkmat));
}

/* ----- AEAD ------------------------------------------------------------- */

static int aead_seal(uint8_t *ct, size_t *ctlen, const uint8_t *pt, size_t ptlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t nonce[RATCHET_NONCE_LEN],
                     const uint8_t mk[RATCHET_MK_LEN]) {
    unsigned long long cl = 0;
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(
            ct, &cl, pt, ptlen, ad, adlen, NULL, nonce, mk) != 0)
        return -1;
    *ctlen = (size_t)cl;
    return 0;
}

static int aead_open(uint8_t *pt, size_t *ptlen, const uint8_t *ct, size_t ctlen,
                     const uint8_t *ad, size_t adlen,
                     const uint8_t nonce[RATCHET_NONCE_LEN],
                     const uint8_t mk[RATCHET_MK_LEN]) {
    unsigned long long ml = 0;
    if (crypto_aead_xchacha20poly1305_ietf_decrypt(
            pt, &ml, NULL, ct, ctlen, ad, adlen, nonce, mk) != 0)
        return -1;
    *ptlen = (size_t)ml;
    return 0;
}

/* ----- init ------------------------------------------------------------- */

int ratchet_gen_keypair(uint8_t pub[RATCHET_DH_LEN], uint8_t priv[RATCHET_DH_LEN]) {
    return hk_x448_keypair(pub, priv);
}

int ratchet_init_alice(ratchet_state *st, const uint8_t root_key[32],
                       const uint8_t peer_dh_pub[RATCHET_DH_LEN]) {
    memset(st, 0, sizeof(*st));
    memcpy(st->rk, root_key, 32);
    if (ratchet_gen_keypair(st->dhs_pub, st->dhs_priv) != 0) return -1;
    memcpy(st->dhr, peer_dh_pub, RATCHET_DH_LEN);
    st->have_dhr = 1;

    uint8_t dh[RATCHET_DH_LEN];
    if (hk_x448_dh(dh, st->dhs_priv, st->dhr) != 0) { sodium_memzero(dh, sizeof(dh)); return -1; }
    kdf_rk(st->rk, dh, st->rk, st->cks);
    st->have_cks = 1;
    sodium_memzero(dh, sizeof(dh));
    return 0;
}

int ratchet_init_bob(ratchet_state *st, const uint8_t root_key[32],
                     const uint8_t dhs_pub[RATCHET_DH_LEN],
                     const uint8_t dhs_priv[RATCHET_DH_LEN]) {
    memset(st, 0, sizeof(*st));
    memcpy(st->rk, root_key, 32);
    memcpy(st->dhs_pub, dhs_pub, RATCHET_DH_LEN);
    memcpy(st->dhs_priv, dhs_priv, RATCHET_DH_LEN);
    /* No sending or receiving chain yet: Bob's first DH ratchet (triggered by
     * the connector's first message) creates both. */
    return 0;
}

/* ----- skipped message keys -------------------------------------------- */

/* Store (DHr, n) -> (mk, nonce), evicting the oldest entry if the cache is
 * full so a long-lived session cannot grow without bound. */
static void skip_store(ratchet_state *st, const uint8_t dhr[RATCHET_DH_LEN],
                       uint32_t n, const uint8_t mk[RATCHET_MK_LEN],
                       const uint8_t nonce[RATCHET_NONCE_LEN]) {
    ratchet_skipped *slot;
    if (st->n_skipped < RATCHET_SKIP_STORE) {
        slot = &st->skipped[st->n_skipped++];
    } else {
        slot = &st->skipped[0];                     /* evict oldest */
        memmove(&st->skipped[0], &st->skipped[1],
                sizeof(st->skipped[0]) * (RATCHET_SKIP_STORE - 1));
        slot = &st->skipped[RATCHET_SKIP_STORE - 1];
    }
    memcpy(slot->dhr, dhr, RATCHET_DH_LEN);
    slot->n = n;
    memcpy(slot->mk, mk, RATCHET_MK_LEN);
    memcpy(slot->nonce, nonce, RATCHET_NONCE_LEN);
    slot->used = 0;
}

/* Try to decrypt with a stored skipped key matching (DHr, n). Returns 0 on a
 * hit (and consumes the key), -1 if no key matched or it failed to open. */
static int try_skipped(ratchet_state *st, const uint8_t hdr_dh[RATCHET_DH_LEN],
                       uint32_t n, const uint8_t *header,
                       const uint8_t *ct, size_t ctlen,
                       uint8_t *pt, size_t *ptlen) {
    for (size_t i = 0; i < st->n_skipped; i++) {
        ratchet_skipped *s = &st->skipped[i];
        if (s->used || s->n != n || memcmp(s->dhr, hdr_dh, RATCHET_DH_LEN) != 0)
            continue;
        if (aead_open(pt, ptlen, ct, ctlen, header, RATCHET_HEADER_LEN,
                      s->nonce, s->mk) != 0)
            return -1;
        /* Consume: wipe and remove from the array. */
        sodium_memzero(s, sizeof(*s));
        memmove(&st->skipped[i], &st->skipped[i + 1],
                sizeof(st->skipped[0]) * (st->n_skipped - i - 1));
        st->n_skipped--;
        return 0;
    }
    return -1;
}

/* Advance the receiving chain, banking message keys, until Nr == until. */
static int skip_message_keys(ratchet_state *st, uint32_t until) {
    if ((uint64_t)st->nr + RATCHET_MAX_SKIP < (uint64_t)until) return -1;
    if (!st->have_ckr) return 0;
    while (st->nr < until) {
        uint8_t ck2[32], mk[RATCHET_MK_LEN], nonce[RATCHET_NONCE_LEN];
        kdf_ck(st->ckr, ck2, mk, nonce);
        memcpy(st->ckr, ck2, 32);
        skip_store(st, st->dhr, st->nr, mk, nonce);
        sodium_memzero(ck2, sizeof(ck2));
        sodium_memzero(mk, sizeof(mk));
        sodium_memzero(nonce, sizeof(nonce));
        st->nr++;
    }
    return 0;
}

/* Perform a DH-ratchet step on receiving a message with a new peer pubkey. */
static int dh_ratchet(ratchet_state *st, const uint8_t hdr_dh[RATCHET_DH_LEN]) {
    st->pn = st->ns;
    st->ns = 0;
    st->nr = 0;
    memcpy(st->dhr, hdr_dh, RATCHET_DH_LEN);
    st->have_dhr = 1;

    uint8_t dh[RATCHET_DH_LEN];
    if (hk_x448_dh(dh, st->dhs_priv, st->dhr) != 0) { sodium_memzero(dh, sizeof(dh)); return -1; }
    kdf_rk(st->rk, dh, st->rk, st->ckr);
    st->have_ckr = 1;
    sodium_memzero(dh, sizeof(dh));

    if (ratchet_gen_keypair(st->dhs_pub, st->dhs_priv) != 0) return -1;
    if (hk_x448_dh(dh, st->dhs_priv, st->dhr) != 0) { sodium_memzero(dh, sizeof(dh)); return -1; }
    kdf_rk(st->rk, dh, st->rk, st->cks);
    st->have_cks = 1;
    sodium_memzero(dh, sizeof(dh));
    return 0;
}

/* ----- encrypt / decrypt ------------------------------------------------ */

int ratchet_encrypt(ratchet_state *st, const uint8_t *pt, size_t ptlen,
                    uint8_t header[RATCHET_HEADER_LEN],
                    uint8_t *ct, size_t *ctlen) {
    if (!st->have_cks) return -1;

    uint8_t ck2[32], mk[RATCHET_MK_LEN], nonce[RATCHET_NONCE_LEN];
    kdf_ck(st->cks, ck2, mk, nonce);
    memcpy(st->cks, ck2, 32);

    memcpy(header, st->dhs_pub, RATCHET_DH_LEN);
    put_u32(header + RATCHET_DH_LEN, st->pn);
    put_u32(header + RATCHET_DH_LEN + 4, st->ns);

    int rc = aead_seal(ct, ctlen, pt, ptlen, header, RATCHET_HEADER_LEN, nonce, mk);
    st->ns++;

    sodium_memzero(ck2, sizeof(ck2));
    sodium_memzero(mk, sizeof(mk));
    sodium_memzero(nonce, sizeof(nonce));
    return rc;
}

int ratchet_decrypt(ratchet_state *st, const uint8_t header[RATCHET_HEADER_LEN],
                    const uint8_t *ct, size_t ctlen,
                    uint8_t *pt, size_t *ptlen) {
    uint8_t hdr_dh[RATCHET_DH_LEN];
    memcpy(hdr_dh, header, RATCHET_DH_LEN);
    uint32_t pn = get_u32(header + RATCHET_DH_LEN);
    uint32_t n  = get_u32(header + RATCHET_DH_LEN + 4);

    /* 1. A previously-skipped key may already cover this message. */
    if (st->n_skipped && try_skipped(st, hdr_dh, n, header, ct, ctlen, pt, ptlen) == 0)
        return 0;

    /* 2. A new ratchet public key means the peer turned the conversation
     *    around: bank any keys left in the current chain, then DH-ratchet. */
    if (!st->have_dhr || memcmp(hdr_dh, st->dhr, RATCHET_DH_LEN) != 0) {
        if (skip_message_keys(st, pn) != 0) return -1;
        if (dh_ratchet(st, hdr_dh) != 0) return -1;
    }

    /* 3. Bank keys for any messages skipped within the current chain. */
    if (skip_message_keys(st, n) != 0) return -1;
    if (!st->have_ckr) return -1;

    /* 4. Derive this message's key and open it. */
    uint8_t ck2[32], mk[RATCHET_MK_LEN], nonce[RATCHET_NONCE_LEN];
    kdf_ck(st->ckr, ck2, mk, nonce);
    memcpy(st->ckr, ck2, 32);

    int rc = aead_open(pt, ptlen, ct, ctlen, header, RATCHET_HEADER_LEN, nonce, mk);
    if (rc == 0) st->nr++;

    sodium_memzero(ck2, sizeof(ck2));
    sodium_memzero(mk, sizeof(mk));
    sodium_memzero(nonce, sizeof(nonce));
    return rc;
}

void ratchet_wipe(ratchet_state *st) {
    sodium_memzero(st, sizeof(*st));
}
