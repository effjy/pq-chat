/*
 * hybrid_kem.h - Post-quantum hybrid KEM for Ciphers.
 *
 * Combines CRYSTALS-Kyber-1024 (NIST level 5, KYBER_K=4) with the X448
 * elliptic-curve Diffie-Hellman, mixing both shared secrets through a
 * BLAKE2b KDF (libsodium's crypto_generichash). The result is a 32-byte
 * symmetric key that stays secure as long as *either* primitive holds,
 * giving classical + post-quantum protection.
 *
 * The hybrid secret key (Kyber sk || X448 sk) is itself wrapped with a
 * password-derived master key (Argon2id), so a single password protects
 * the whole keypair -- mirroring the Axis design.
 */
#ifndef CIPHERS_HYBRID_KEM_H
#define CIPHERS_HYBRID_KEM_H

#include <stdint.h>
#include <stddef.h>

/* Kyber-1024 sizes (see kyber/api.h). */
#define HK_KYBER_PUBLICKEYBYTES   1568
#define HK_KYBER_SECRETKEYBYTES   3168
#define HK_KYBER_CIPHERTEXTBYTES  1568
#define HK_KYBER_SSBYTES          32

/* X448 raw key sizes. */
#define HK_X448_PUBKEY_LEN        56
#define HK_X448_PRIVKEY_LEN       56

/* Combined hybrid public/secret key material. */
#define HK_PK_LEN   (HK_KYBER_PUBLICKEYBYTES + HK_X448_PUBKEY_LEN)   /* 1624 */
#define HK_SK_LEN   (HK_KYBER_SECRETKEYBYTES + HK_X448_PRIVKEY_LEN)  /* 3224 */

/* KEM ciphertext = Kyber ciphertext || X448 ephemeral public key. */
#define HK_KEM_CT_LEN (HK_KYBER_CIPHERTEXTBYTES + HK_X448_PUBKEY_LEN) /* 1624 */

/* Derived symmetric key length (used directly as the AEAD file key). */
#define HK_SHARED_SECRET_LEN 32

/* Generate a hybrid keypair. Public key buffers receive Kyber and X448
 * public keys; secret key buffers receive the matching private keys.
 * Returns 0 on success, -1 on failure. */
int hk_generate_keypair(uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES],
                        uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES],
                        uint8_t x448_pk[HK_X448_PUBKEY_LEN],
                        uint8_t x448_sk[HK_X448_PRIVKEY_LEN]);

/* Encapsulate to (kyber_pk, x448_pk): produce a 32-byte shared secret and
 * the KEM ciphertext (HK_KEM_CT_LEN bytes). Returns 0 on success. */
int hk_encapsulate(uint8_t shared_secret[HK_SHARED_SECRET_LEN],
                   uint8_t kem_ct[HK_KEM_CT_LEN],
                   const uint8_t kyber_pk[HK_KYBER_PUBLICKEYBYTES],
                   const uint8_t x448_pk[HK_X448_PUBKEY_LEN]);

/* Decapsulate kem_ct with (kyber_sk, x448_sk): recover the 32-byte shared
 * secret. Returns 0 on success, -1 on failure. */
int hk_decapsulate(uint8_t shared_secret[HK_SHARED_SECRET_LEN],
                   const uint8_t kem_ct[HK_KEM_CT_LEN],
                   const uint8_t kyber_sk[HK_KYBER_SECRETKEYBYTES],
                   const uint8_t x448_sk[HK_X448_PRIVKEY_LEN]);

/* ----- Standalone X448 (for the Double Ratchet's DH step) --------------- *
 * The Diffie-Hellman ratchet in ratchet.c needs raw X448 keypairs and a
 * scalar-mult, independent of the KEM. These thin wrappers expose the same
 * OpenSSL-backed X448 used inside the hybrid KEM so the ratchet shares one
 * vetted implementation. */

/* Generate an X448 keypair. Returns 0 on success, -1 on failure. */
int hk_x448_keypair(uint8_t pub[HK_X448_PUBKEY_LEN],
                    uint8_t priv[HK_X448_PRIVKEY_LEN]);

/* Compute the X448 shared point out = priv * pub (56 raw bytes). The caller
 * is expected to run the result through a KDF. Returns 0 on success, -1 on
 * failure (e.g. an invalid peer public key). */
int hk_x448_dh(uint8_t out[HK_X448_PUBKEY_LEN],
               const uint8_t priv[HK_X448_PRIVKEY_LEN],
               const uint8_t pub[HK_X448_PUBKEY_LEN]);

#endif /* CIPHERS_HYBRID_KEM_H */
