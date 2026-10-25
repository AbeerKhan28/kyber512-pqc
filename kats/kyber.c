#include "kyber.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "fips202.h"

#ifndef KAT_TEST
// ALL Raspberry Pi Pico hardware headers MUST go inside here
#include "pico/stdlib.h"
#include "pico/multicore.h"
#include "dma_utils.h"
#include "hardware/structs/rosc.h"

void randombytes(uint8_t *out, size_t outlen) {
    uint8_t raw_buf[256]; // Oversample buffer
    for (size_t i = 0; i < sizeof(raw_buf); i++) {
        uint8_t byte = 0;
        for (int b = 0; b < 8; b++) {
            byte = (byte << 1) | (rosc_hw->randombit & 1); 
        }
        raw_buf[i] = byte;
    }
    // Condition raw rosc bits through SHAKE256
    shake256(out, outlen, raw_buf, sizeof(raw_buf));
}

#else
// Route randombytes to the desktop testing harness instead
extern void randombytes(uint8_t *out, size_t outlen);
#endif

//====================================================================
// CONSTANT-TIME COMPARISON (Side-Channel Defense)
// Compares two arrays without early-exit branching.
// Returns 0 if identical, non-zero if different.
// ====================================================================
static uint8_t constant_time_cmp(const uint8_t *a, const uint8_t *b, size_t len) {
    volatile uint8_t result = 0;  // CRITICAL: volatile prevents compiler early-exit optimizations
    for (size_t i = 0; i < len; i++) {
        result |= (a[i] ^ b[i]); // XOR differences, OR them together
    }
    return result; 
}

// ====================================================================



// ====================================================================
// 2. STANDARD KYBER MATH HELPERS (CBD & PRF)
// ====================================================================

// Generalized SamplePolyCBD_eta (FIPS 203, Algorithm 8)
void kyber_cbd_eta(int16_t *r, const uint8_t *buf, int eta) {
    for (int i = 0; i < N; i++) {
        int a = 0, b = 0;
        for (int j = 0; j < eta; j++) {
            int ia = 2*i*eta + j;
            int ib = 2*i*eta + eta + j;
            a += (buf[ia / 8] >> (ia % 8)) & 1;
            b += (buf[ib / 8] >> (ib % 8)) & 1;
        }
        r[i] = (int16_t)(a - b);
    }
}

// PRF_eta(seed, nonce) = SHAKE256(seed || nonce, 8 * 64 * eta) bits
void prf_noise(uint8_t *out, const uint8_t *seed, uint8_t nonce, int eta) {
    uint8_t ext_seed[33];
    memcpy(ext_seed, seed, 32);
    ext_seed[32] = nonce;
    shake256(out, 64 * eta, ext_seed, 33); 
}

// 1. Compress a coefficient from Q (3329) down to 'd' bits
#define KYBER_Q 3329
#define BARRETT_SHIFT 33
static const uint64_t BARRETT_V = ((1ULL << BARRETT_SHIFT) + (KYBER_Q / 2)) / KYBER_Q;

// floor(num / Q) with no data-dependent-latency division
static inline uint32_t div_q_const_time(uint32_t num) {
    uint64_t t = (uint64_t)num * BARRETT_V;
    return (uint32_t)(t >> BARRETT_SHIFT);
}

uint16_t compress_coeff(uint16_t x, int d) {
    uint32_t num = ((uint32_t)x << d) + (KYBER_Q >> 1);
    uint32_t q_est = div_q_const_time(num);
    return (uint16_t)(q_est & ((1u << d) - 1));
}

// 2. Decompress a coefficient from 'd' bits back to Q (3329)
uint16_t decompress_coeff(uint16_t x, int d) {
    uint32_t temp = ((uint32_t)x * 3329) + (1 << (d - 1));
    return temp >> d;
}

// ====================================================================
// 3. KEY GENERATION (Alice)
// ====================================================================
void keygen(kyber_keypair *kp) {
    int16_t e[K][N]; 

    // A. Seed Expansion (Hardware TRNG -> SHA3-512)
    uint8_t d_k[33];
    randombytes(d_k, 32); 
    d_k[32] = 2; // Domain separation for ML-KEM-512 (k=2)
    
    uint8_t hashed_seeds[64];
    sha3_512(hashed_seeds, d_k, 33); 
    uint8_t *public_seed = hashed_seeds;      
    uint8_t *noise_seed = hashed_seeds + 32;  

    memcpy(kp->seed_rho, public_seed, 32);

    // B. Generate Secret (s) and Error (e) with CBD + Nonces
    uint8_t noise_buf[192]; 
    uint8_t nonce = 0; 
    
    // 1. Generate all 's' polynomials first (Nonces 0 and 1)
    for(int i=0; i<K; i++) {
        prf_noise(noise_buf, noise_seed, nonce++, 3);
        kyber_cbd_eta(kp->s[i], noise_buf, 3);
    }
    
    // 2. Generate all 'e' polynomials next (Nonces 2 and 3)
    for(int i=0; i<K; i++) {
        prf_noise(noise_buf, noise_seed, nonce++, 3);
        kyber_cbd_eta(e[i], noise_buf, 3);
    }

    // C. Generate Matrix A (NIST FIPS-203 Standard)
    uint8_t ext_seed[34];
    uint8_t buf[672]; 
    memcpy(ext_seed, public_seed, 32);
    
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ext_seed[32] = j; // FIPS 203 mandates j then i
            ext_seed[33] = i; 
            shake128(buf, sizeof(buf), ext_seed, 34);
            
            int ctr = 0, pos = 0;
            while (ctr < 256 && pos + 3 <= sizeof(buf)) {
                uint16_t d1 = buf[pos] | ((uint16_t)buf[pos+1] << 8);
                uint16_t d2 = (buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4);
                pos += 3;
                
                d1 &= 0x0FFF;
                if (d1 < 3329 && ctr < 256) kp->A[i][j][ctr++] = d1;
                
                d2 &= 0x0FFF;
                if (d2 < 3329 && ctr < 256) kp->A[i][j][ctr++] = d2;
            }
        }
    }

    // D. Calculate Public Key: t = A * s + e
 // D. Convert Secret and Error to NTT domain, calculate t = A*s + e
    int16_t s_hat[K][N], e_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) s_hat[i][x] = kp->s[i][x];
        ntt(s_hat[i]);              // s_hat[i] = NTT(s[i])
        for (int x = 0; x < N; x++) e_hat[i][x] = e[i][x];
        ntt(e_hat[i]);              // e_hat[i] = NTT(e[i])
    }
    
    // t_hat = A_hat . s_hat + e_hat  -- pure NTT domain, NO final intt()
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) kp->t[i][x] = e_hat[i][x];
        for (int j = 0; j < K; j++) {
            poly_basemul_acc(kp->t[i], kp->A[i][j], s_hat[j]);
        }
    }
    
    // kp->s now permanently stores s_hat (NTT domain) -- overwrite it:
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) kp->s[i][x] = s_hat[i][x];
    }
    
  
    // Generate the Implicit Rejection Seed (z) via TRNG
    randombytes(kp->z, 32);

// FIPS 203: Precompute H(ek) during Key Generation
    uint8_t pk_bytes[800];
    pack_pk(pk_bytes, kp->t, kp->seed_rho);
    sha3_256(kp->H_ek, pk_bytes, 800);
}
// ==========================================================
// NIST STANDARD BIT-PACKING & MATRIX GENERATION
// ==========================================================

// Pack 256 coefficients of an int16_t array into 384 bytes (12 bits per coefficient)
void poly_tobytes(uint8_t *r, const int16_t *a) {
    for (int i = 0; i < 256 / 2; i++) {
        uint16_t t0 = (uint16_t)a[2 * i];
        uint16_t t1 = (uint16_t)a[2 * i + 1];
        r[3 * i + 0] = (uint8_t)(t0 & 0xFF);
        r[3 * i + 1] = (uint8_t)((t0 >> 8) | ((t1 & 0x0F) << 4));
        r[3 * i + 2] = (uint8_t)((t1 >> 4) & 0xFF);
    }
}

// Alice's complete Public Key standard assembly
void pack_pk(uint8_t *pk, const int16_t t[2][256], const uint8_t *seed_rho) {
    poly_tobytes(pk + 0,   t[0]);
    poly_tobytes(pk + 384, t[1]);
    memcpy(pk + 768, seed_rho, 32);
}

// Unpack 384 bytes back into 256 normal 16-bit coefficients
void poly_frombytes(int16_t *r, const uint8_t *a) {
    for (int i = 0; i < 256 / 2; i++) {
        r[2 * i + 0] = (int16_t)(a[3 * i + 0] | ((uint16_t)(a[3 * i + 1] & 0x0F) << 8));
        r[2 * i + 1] = (int16_t)((a[3 * i + 1] >> 4) | ((uint16_t)a[3 * i + 2] << 4));
    }
}

// Bob unpacks Alice's standard public key
int unpack_pk(kyber_keypair *pk_struct, const uint8_t *pk) {
    poly_frombytes(pk_struct->t[0], pk + 0);
    poly_frombytes(pk_struct->t[1], pk + 384);
    memcpy(pk_struct->seed_rho, pk + 768, 32);
    
    // FIPS 203 Modulus Check
    for (int i = 0; i < 2; i++) {
        for (int x = 0; x < 256; x++) {
            if (pk_struct->t[i][x] >= 3329) {
                return -1; // Return failure instead of while(1)
            }
        }
    }
    
    gen_matrix_A(pk_struct->A, pk_struct->seed_rho);
    return 0; // Success
}


// Assembles the 1632-byte Secret Key (dk)
void pack_sk(uint8_t *sk, kyber_keypair *kp) {
    poly_tobytes(sk + 0, kp->s[0]);
    poly_tobytes(sk + 384, kp->s[1]);
    pack_pk(sk + 768, kp->t, kp->seed_rho); // Embeds ek
    memcpy(sk + 1568, kp->H_ek, 32);
    memcpy(sk + 1600, kp->z, 32);
}

// Parses the 1632-byte Secret Key (dk)
int unpack_sk(kyber_keypair *kp, const uint8_t *sk) {
    poly_frombytes(kp->s[0], sk + 0);
    poly_frombytes(kp->s[1], sk + 384);
    
    // Unpack embedded ek (which handles the modulus check and matrix A generation)
    if (unpack_pk(kp, sk + 768) != 0) return -1;

    // FIPS 203 §7.3 Hash Check: H(ek) must match the value stored in dk.
    // Recompute over the embedded ek bytes rather than trusting the stored field.
    uint8_t computed_H_ek[32];
    sha3_256(computed_H_ek, sk + 768, 800);
    if (constant_time_cmp(computed_H_ek, sk + 1568, 32) != 0) return -1;

    memcpy(kp->H_ek, sk + 1568, 32);
    memcpy(kp->z, sk + 1600, 32);
    return 0;
}




// Generates Matrix A from a 32-byte seed using SHAKE-128
void gen_matrix_A(int16_t A[2][2][256], const uint8_t *seed_rho) {
    uint8_t ext_seed[34];
    uint8_t buf[672]; 
    memcpy(ext_seed, seed_rho, 32);
    
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < 2; j++) {
            ext_seed[32] = j; 
            ext_seed[33] = i; 
            shake128(buf, sizeof(buf), ext_seed, 34);
            
            int ctr = 0, pos = 0;
            while (ctr < 256 && pos + 3 <= sizeof(buf)) {
                uint16_t d1 = buf[pos] | ((uint16_t)buf[pos+1] << 8);
                uint16_t d2 = (buf[pos+1] >> 4) | ((uint16_t)buf[pos+2] << 4);
                pos += 3;
                
                d1 &= 0x0FFF;
                if (d1 < 3329 && ctr < 256) A[i][j][ctr++] = d1;
                
                d2 &= 0x0FFF;
                if (d2 < 3329 && ctr < 256) A[i][j][ctr++] = d2;
            }
        }
    }
}

// ====================================================================
// 4. ENCAPSULATION (Bob)
// ====================================================================
void encapsulate(kyber_keypair *pk, uint8_t *ct, uint8_t *shared_key) {
    int16_t u[K][N];
    int16_t v[N];
    int16_t r_poly[K][N], e1[K][N], e2[N];

    // A & B. Generate Random Message & FIPS 203 Key Derivation: (K, r) = G(m || H(ek))
    uint8_t m[32];
    randombytes(m, 32); 

    uint8_t pk_bytes[800];
    pack_pk(pk_bytes, pk->t, pk->seed_rho); 
    
    uint8_t H_ek[32];
    sha3_256(H_ek, pk_bytes, 800); 
    
    uint8_t m_Hek[64];
    memcpy(m_Hek, m, 32);
    memcpy(m_Hek + 32, H_ek, 32);
    
    uint8_t Kr[64];
    sha3_512(Kr, m_Hek, 64); 
    
    memcpy(shared_key, Kr, 32); 
    uint8_t *r_seed = Kr + 32;  

    // C. Generate Noise with CBD + Nonces
    uint8_t noise_buf[192]; 
    uint8_t nonce = 0; 
    for(int i = 0; i < K; i++) {
        prf_noise(noise_buf, r_seed, nonce++, 3);
        kyber_cbd_eta(r_poly[i], noise_buf, 3);
    }
    for(int i = 0; i < K; i++) {
        prf_noise(noise_buf, r_seed, nonce++, 2);
        kyber_cbd_eta(e1[i], noise_buf, 2);
    }
    prf_noise(noise_buf, r_seed, nonce++, 2);
    kyber_cbd_eta(e2, noise_buf, 2);

    // D. Matrix Math for u: u = A^T * r_poly + e1
   // Transform r to NTT domain once
    int16_t r_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) r_hat[i][x] = r_poly[i][x];
        ntt(r_hat[i]);
    }

    // D. Matrix Math for u: u = INTT(A^T * r_hat) + e1
    for (int i = 0; i < K; i++) {
        int16_t u_hat[N] = {0};
        for (int j = 0; j < K; j++) {
            poly_basemul_acc(u_hat, pk->A[j][i], r_hat[j]);
        }
        intt(u_hat);
        for (int x = 0; x < N; x++) u[i][x] = mod_q(u_hat[x] + e1[i][x]);
    }

    // E. Math for v: v = INTT(t^T * r_hat) + e2 + m
    int16_t v_hat[N] = {0};
    for (int i = 0; i < K; i++) {
        poly_basemul_acc(v_hat, pk->t[i], r_hat[i]);
    }
    intt(v_hat);
    
    for (int x = 0; x < N; x++) v[x] = mod_q(v_hat[x] + e2[x]);
    for(int i = 0; i < N; i++) { 
        int bit = (m[i / 8] >> (i % 8)) & 1;
        v[i] = mod_q(v[i] + (bit * 1665)); 
    }

    // ====================================================================
    // COMPRESS AND PACK INTO CIPHERTEXT (ct)
    // ====================================================================
    int offset = 0;

    // 1. Compress Vector U (10 bits)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint16_t t0 = compress_coeff(u[i][4*j + 0], 10);
            uint16_t t1 = compress_coeff(u[i][4*j + 1], 10);
            uint16_t t2 = compress_coeff(u[i][4*j + 2], 10);
            uint16_t t3 = compress_coeff(u[i][4*j + 3], 10);

            ct[offset++] = (t0 >> 0);
            ct[offset++] = (t0 >> 8) | (t1 << 2);
            ct[offset++] = (t1 >> 6) | (t2 << 4);
            ct[offset++] = (t2 >> 4) | (t3 << 6);
            ct[offset++] = (t3 >> 2);
        }
    }

    // 2. Compress Vector V (4 bits)
    for(int j = 0; j < N / 2; j++) {
        uint16_t t0 = compress_coeff(v[2*j + 0], 4);
        uint16_t t1 = compress_coeff(v[2*j + 1], 4);
        ct[offset++] = t0 | (t1 << 4);
    }
}

// ====================================================================
// 5. DECAPSULATION (Alice)
// ====================================================================
void decapsulate(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key) {
    int16_t u[K][N];
    int16_t v[N];
    for(int i=0; i<32; i++) shared_key[i] = 0;

    // ====================================================================
    // UNPACK AND DECOMPRESS FROM CIPHERTEXT (ct)
    // ====================================================================
    int offset = 0;

    // 1. Unpack Vector U (10 bits back to 3329)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint8_t b0 = ct[offset++];
            uint8_t b1 = ct[offset++];
            uint8_t b2 = ct[offset++];
            uint8_t b3 = ct[offset++];
            uint8_t b4 = ct[offset++];

            uint16_t t0 = (b0 >> 0) | ((uint16_t)(b1 & 0x03) << 8);
            uint16_t t1 = (b1 >> 2) | ((uint16_t)(b2 & 0x0F) << 6);
            uint16_t t2 = (b2 >> 4) | ((uint16_t)(b3 & 0x3F) << 4);
            uint16_t t3 = (b3 >> 6) | ((uint16_t)(b4 & 0xFF) << 2);

            u[i][4*j + 0] = decompress_coeff(t0, 10);
            u[i][4*j + 1] = decompress_coeff(t1, 10);
            u[i][4*j + 2] = decompress_coeff(t2, 10);
            u[i][4*j + 3] = decompress_coeff(t3, 10);
        }
    }

    // 2. Unpack Vector V (4 bits back to 3329)
    for(int j = 0; j < N / 2; j++) {
        uint8_t b0 = ct[offset++];
        uint16_t t0 = b0 & 0x0F;
        uint16_t t1 = b0 >> 4;

        v[2*j + 0] = decompress_coeff(t0, 4);
        v[2*j + 1] = decompress_coeff(t1, 4);
    }

    // A. Recover Message (m_prime)
 // A. Recover Message (m_prime)
    int16_t u_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) u_hat[i][x] = u[i][x];
        ntt(u_hat[i]);
    }
    
    int16_t s_u_hat[N] = {0};
    for (int i = 0; i < K; i++) {
        poly_basemul_acc(s_u_hat, kp->s[i], u_hat[i]); // kp->s is already in NTT domain
    }
    intt(s_u_hat);
    
    uint8_t m_prime[32] = {0};
    for(int i=0; i<N; i++) {
        int16_t msg_bit = mod_q(v[i] - s_u_hat[i]);
        int bit = compress_coeff((uint16_t)msg_bit, 1);
        m_prime[i / 8] |= (bit << (i % 8));
    }

    // B. FIPS 203 Key Derivation: (K', r') = G(m' || H(ek))
 
    uint8_t m_Hek[64];
    memcpy(m_Hek, m_prime, 32);
    memcpy(m_Hek + 32, kp->H_ek, 32); // Use precomputed hash directly
    
    uint8_t Kr[64];
    sha3_512(Kr, m_Hek, 64); 
    
    uint8_t valid_key[32];
    memcpy(valid_key, Kr, 32); // K'
    uint8_t *r_seed = Kr + 32; // r'


    // C. FUJISAKI-OKAMOTO RE-ENCRYPTION TRANSFORM
    int16_t u_prime[K][N], v_prime[N], r_poly[K][N], e1[K][N], e2[N];
    uint8_t noise_buf[192]; 
    uint8_t nonce = 0; 

    // Re-create Bob's exact CBD Noise
    for(int i = 0; i < K; i++) {
        prf_noise(noise_buf, r_seed, nonce++, 3);
        kyber_cbd_eta(r_poly[i], noise_buf, 3);
     }
    for(int i = 0; i < K; i++) {  
        prf_noise(noise_buf, r_seed, nonce++, 2);
        kyber_cbd_eta(e1[i], noise_buf, 2);
    }
    prf_noise(noise_buf, r_seed, nonce++, 2);
    kyber_cbd_eta(e2, noise_buf, 2);

    // Re-calculate u' = A^T * r_poly + e1
    
    // Transform r_poly to NTT domain once
    int16_t r_hat[K][N];
    for (int i = 0; i < K; i++) {
        for (int x = 0; x < N; x++) r_hat[i][x] = r_poly[i][x];
        ntt(r_hat[i]);
    }

    // Re-calculate u' = INTT(A^T * r_hat) + e1
    for(int i=0; i<K; i++) {
        int16_t u_hat_prime[N] = {0};
        for(int j=0; j<K; j++) {
            poly_basemul_acc(u_hat_prime, kp->A[j][i], r_hat[j]);
        }
        intt(u_hat_prime);
        for(int x=0; x<N; x++) u_prime[i][x] = mod_q(u_hat_prime[x] + e1[i][x]);
    }

    // Re-calculate v' = INTT(t^T * r_hat) + e2 + m_prime
    int16_t v_hat_prime[N] = {0};
    for(int i=0; i<K; i++) {
        poly_basemul_acc(v_hat_prime, kp->t[i], r_hat[i]);
    }
    intt(v_hat_prime);
    
    for(int x=0; x<N; x++) v_prime[x] = mod_q(v_hat_prime[x] + e2[x]);
    for(int i=0; i<N; i++) { 
        int bit = (m_prime[i / 8] >> (i % 8)) & 1;
        v_prime[i] = mod_q(v_prime[i] + (bit * 1665)); 
    }



    // C. The Verification Check
    int check_failed = 0;
    uint8_t ct_prime[768];
    int offset_prime = 0;

    // 1. Compress Vector u_prime (10 bits)
    for(int i = 0; i < K; i++) {
        for(int j = 0; j < N / 4; j++) {
            uint16_t t0 = compress_coeff(u_prime[i][4*j + 0], 10);
            uint16_t t1 = compress_coeff(u_prime[i][4*j + 1], 10);
            uint16_t t2 = compress_coeff(u_prime[i][4*j + 2], 10);
            uint16_t t3 = compress_coeff(u_prime[i][4*j + 3], 10);

            ct_prime[offset_prime++] = (t0 >> 0);
            ct_prime[offset_prime++] = (t0 >> 8) | (t1 << 2);
            ct_prime[offset_prime++] = (t1 >> 6) | (t2 << 4);
            ct_prime[offset_prime++] = (t2 >> 4) | (t3 << 6);
            ct_prime[offset_prime++] = (t3 >> 2);
        }
    }

    // 2. Compress Vector v_prime (4 bits)
    for(int j = 0; j < N / 2; j++) {
        uint16_t t0 = compress_coeff(v_prime[2*j + 0], 4);
        uint16_t t1 = compress_coeff(v_prime[2*j + 1], 4);
        ct_prime[offset_prime++] = t0 | (t1 << 4);
    }

    // Compare the original received ct with our re-encrypted ct_prime
    check_failed = constant_time_cmp(ct, ct_prime, 768);

    // ====================================================================
    // D. NEW: IMPLICIT REJECTION & DOMAIN SEPARATION (FIPS 203)
    // ====================================================================
    // 1. Generate the "Junk" Key using Alice's secret 'z' and raw ciphertext
    // FIPS 203: J(z || c) where J is SHAKE-256
    uint8_t junk_key[32];
    uint8_t junk_buffer[32 + 768]; 
    for(int i = 0; i < 32; i++) junk_buffer[i] = kp->z[i];
    for(int i = 0; i < 768; i++) junk_buffer[i + 32] = ct[i];
    
    shake256(junk_key, 32, junk_buffer, 32 + 768);

    // 2. The Secure Constant-Time Move (CMOV)
    uint8_t b = (uint8_t)check_failed;
    b |= b >> 4; 
    b |= b >> 2; 
    b |= b >> 1;
    volatile uint8_t mask = -(b & 1); // Now cleanly 0x00 or 0xFF
    for(int i = 0; i < 32; i++) {
        shared_key[i] = (valid_key[i] & ~mask) | (junk_key[i] & mask);
    }
}