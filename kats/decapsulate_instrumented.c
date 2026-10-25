// decapsulate_instrumented.c
//
// A byte-for-byte functional clone of decapsulate() from kyber.c, with
// on-chip cycle checkpoints inserted at 5 natural boundaries so TVLA can
// be run independently on each segment. This exists ONLY to localize the
// leak found by the full-function TVLA -- production code should keep
// using the real decapsulate().
//
// Segments:
//   seg[0] = unpack/decompress ct -> u,v
//   seg[1] = message recovery (NTT(u), s^T u, compress to m')
//   seg[2] = key derivation (Kr = G(m' || H(ek)))
//   seg[3] = FO re-encryption (CBD, NTT x3, recompute u',v', pack ct')
//   seg[4] = compare + implicit-rejection CMOV
//
// segment_cycles[] must point to a uint32_t[5] buffer.

#include <string.h>
#include <stdint.h>
#include "kyber.h"

// Same free-running SysTick reader as tvla_harness.c (duplicated here to
// keep this file self-contained / independently compilable).
#define SYST_CVR (*(volatile uint32_t *)0xE000E018u)
#define SYST_RELOAD_MAX 0x00FFFFFFu

static inline uint32_t cc_read(void) { return SYST_CVR; }
static inline uint32_t cc_elapsed(uint32_t start_val, uint32_t end_val) {
    return (end_val <= start_val) ? (start_val - end_val)
                                   : (start_val + (SYST_RELOAD_MAX + 1u - end_val));
}

// Declared in kyber.c but not in kyber.h -- forward-declare what we need.
extern void kyber_cbd_eta(int16_t *r, const uint8_t *buf, int eta);
extern void prf_noise(uint8_t *out, const uint8_t *seed, uint8_t nonce, int eta);
extern uint16_t compress_coeff(uint16_t x, int d);
extern uint16_t decompress_coeff(uint16_t x, int d);
extern void sha3_512(uint8_t *out, const uint8_t *in, size_t inlen);
extern void shake256(uint8_t *out, size_t outlen, const uint8_t *in, size_t inlen);

// Local constant-time compare (identical to the static one in kyber.c --
// duplicated since the original is file-scoped `static`).
static uint8_t local_ct_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;
    for (size_t i = 0; i < len; i++) result |= (a[i] ^ b[i]);
    return result;
}

void decapsulate_instrumented(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key,
                               uint32_t *segment_cycles) {
    int16_t u[K][N];
    int16_t v[N];
    for (int i = 0; i < 32; i++) shared_key[i] = 0;

    uint32_t t0 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t0

    // ---- Segment 0: unpack/decompress ct -> u, v ----
    int offset = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N / 4; j++) {
            uint8_t b0 = ct[offset++], b1 = ct[offset++], b2 = ct[offset++];
            uint8_t b3 = ct[offset++], b4 = ct[offset++];
            uint16_t t0v = (b0 >> 0) | ((uint16_t)(b1 & 0x03) << 8);
            uint16_t t1v = (b1 >> 2) | ((uint16_t)(b2 & 0x0F) << 6);
            uint16_t t2v = (b2 >> 4) | ((uint16_t)(b3 & 0x3F) << 4);
            uint16_t t3v = (b3 >> 6) | ((uint16_t)(b4 & 0xFF) << 2);
            u[i][4*j + 0] = decompress_coeff(t0v, 10);
            u[i][4*j + 1] = decompress_coeff(t1v, 10);
            u[i][4*j + 2] = decompress_coeff(t2v, 10);
            u[i][4*j + 3] = decompress_coeff(t3v, 10);
        }
    }
    for (int j = 0; j < N / 2; j++) {
        uint8_t b0 = ct[offset++];
        v[2*j + 0] = decompress_coeff(b0 & 0x0F, 4);
        v[2*j + 1] = decompress_coeff(b0 >> 4, 4);
    }

    uint32_t t1 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t1
    segment_cycles[0] = cc_elapsed(t0, t1);

    // ---- Segment 1: message recovery ----
    int16_t u_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) u_hat[i][x] = u[i][x];
        ntt(u_hat[i]);
    }
    int16_t s_u_hat[N] = {0};
    for (int i = 0; i < K; i++) poly_basemul_acc(s_u_hat, kp->s[i], u_hat[i]);
    intt(s_u_hat);

    uint8_t m_prime[32] = {0};
    for (int i = 0; i < N; i++) {
        int16_t msg_bit = mod_q(v[i] - s_u_hat[i]);
        int bit = compress_coeff((uint16_t)msg_bit, 1);
        m_prime[i / 8] |= (bit << (i % 8));
    }

    uint32_t t2 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t2
    segment_cycles[1] = cc_elapsed(t1, t2);

    // ---- Segment 2: key derivation Kr = G(m' || H(ek)) ----
    uint8_t m_Hek[64];
    memcpy(m_Hek, m_prime, 32);
    memcpy(m_Hek + 32, kp->H_ek, 32);
    uint8_t Kr[64];
    sha3_512(Kr, m_Hek, 64);
    uint8_t valid_key[32];
    memcpy(valid_key, Kr, 32);
    uint8_t *r_seed = Kr + 32;

    uint32_t t3 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t3
    segment_cycles[2] = cc_elapsed(t2, t3);

    // ---- Segment 3: FO re-encryption ----
    int16_t u_prime[K][N], v_prime[N], r_poly[K][N], e1[K][N], e2[N];
    uint8_t noise_buf[192];
    uint8_t nonce = 0;

    for (int i = 0; i < K; i++) {
        prf_noise(noise_buf, r_seed, nonce++, 3);
        kyber_cbd_eta(r_poly[i], noise_buf, 3);
    }
    for (int i = 0; i < K; i++) {
        prf_noise(noise_buf, r_seed, nonce++, 2);
        kyber_cbd_eta(e1[i], noise_buf, 2);
    }
    prf_noise(noise_buf, r_seed, nonce++, 2);
    kyber_cbd_eta(e2, noise_buf, 2);

    int16_t r_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) r_hat[i][x] = r_poly[i][x];
        ntt(r_hat[i]);
    }

    for (int i = 0; i < K; i++) {
        int16_t u_hat_prime[N] = {0};
        for (int j = 0; j < K; j++) poly_basemul_acc(u_hat_prime, kp->A[j][i], r_hat[j]);
        intt(u_hat_prime);
        for (int x = 0; x < N; x++) u_prime[i][x] = mod_q(u_hat_prime[x] + e1[i][x]);
    }

    int16_t v_hat_prime[N] = {0};
    for (int i = 0; i < K; i++) poly_basemul_acc(v_hat_prime, kp->t[i], r_hat[i]);
    intt(v_hat_prime);
    for (int x = 0; x < N; x++) v_prime[x] = mod_q(v_hat_prime[x] + e2[x]);
    for (int i = 0; i < N; i++) {
        int bit = (m_prime[i / 8] >> (i % 8)) & 1;
        v_prime[i] = mod_q(v_prime[i] + (bit * 1665));
    }

    uint8_t ct_prime[768];
    int offset_prime = 0;
    for (int i = 0; i < K; i++) {
        for (int j = 0; j < N / 4; j++) {
            uint16_t t0v = compress_coeff(u_prime[i][4*j + 0], 10);
            uint16_t t1v = compress_coeff(u_prime[i][4*j + 1], 10);
            uint16_t t2v = compress_coeff(u_prime[i][4*j + 2], 10);
            uint16_t t3v = compress_coeff(u_prime[i][4*j + 3], 10);
            ct_prime[offset_prime++] = (t0v >> 0);
            ct_prime[offset_prime++] = (t0v >> 8) | (t1v << 2);
            ct_prime[offset_prime++] = (t1v >> 6) | (t2v << 4);
            ct_prime[offset_prime++] = (t2v >> 4) | (t3v << 6);
            ct_prime[offset_prime++] = (t3v >> 2);
        }
    }
    for (int j = 0; j < N / 2; j++) {
        uint16_t t0v = compress_coeff(v_prime[2*j + 0], 4);
        uint16_t t1v = compress_coeff(v_prime[2*j + 1], 4);
        ct_prime[offset_prime++] = t0v | (t1v << 4);
    }

    uint32_t t4 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t4
    segment_cycles[3] = cc_elapsed(t3, t4);

    // ---- Segment 4: compare + implicit-rejection CMOV ----
    int check_failed = local_ct_cmp(ct, ct_prime, 768);

    uint8_t junk_key[32];
    uint8_t junk_buffer[32 + 768];
    for (int i = 0; i < 32; i++) junk_buffer[i] = kp->z[i];
    for (int i = 0; i < 768; i++) junk_buffer[i + 32] = ct[i];
    shake256(junk_key, 32, junk_buffer, 32 + 768);

    uint8_t b = (uint8_t)check_failed;
    b |= b >> 4; b |= b >> 2; b |= b >> 1;
    volatile uint8_t mask = -(b & 1);
    for (int i = 0; i < 32; i++)
        shared_key[i] = (valid_key[i] & ~mask) | (junk_key[i] & mask);

    uint32_t t5 = cc_read();
    asm volatile("" ::: "memory");  // barrier: prevent reordering across t5
    segment_cycles[4] = cc_elapsed(t4, t5);
}
