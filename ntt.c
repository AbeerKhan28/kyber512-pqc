#include "ntt.h"
#include "math_utils.h"
#include <stdint.h>



int16_t W[128];           // Zetas (Twiddle factors) for NTT
int16_t odd_powers[128];  // Precomputed Zetas for Base Multiplication
int16_t odd_powers_br[128]; // NEW: Precomputed bit-reversed lookup

// ====================================================================
// 7-bit bit reversal for standard Kyber Butterfly
// ====================================================================
uint8_t bitrev7(uint8_t x) {
    uint8_t r = 0;
    for (int i = 0; i < 7; i++) {
        r |= ((x >> i) & 1) << (6 - i);
    }
    return r;
}

// ====================================================================
// Standard Kyber Zeta Initialization
// ====================================================================
void init_ntt() {
    int32_t current = 1;
    int16_t powers[128];
    
    for(int i = 0; i < 128; i++) {
        powers[i] = (current * 2285) % 3329; // Scale by R mod Q
        current = mod_q(current * 17); 
    }
    
    for(int i = 0; i < 128; i++) {
        W[i] = powers[bitrev7(i)];
    }

    current = 17; 
    for(int i = 0; i < 128; i++) {
        odd_powers[i] = (current * 2285) % 3329; // Scale by R mod Q
        current = mod_q(current * 17); 
        current = mod_q(current * 17); 
    }
    for (int i = 0; i < 128; i++) {
        odd_powers_br[i] = odd_powers[bitrev7(i)];
    }
}

int16_t mul_mod(int16_t a, int16_t b) {
    return montgomery_reduce((int32_t)a * b);
}

// ====================================================================
// Standard Kyber Cooley-Tukey Butterfly NTT
// ====================================================================
void ntt(int16_t *a) {
    int len, start, j, k;
    int16_t zeta, t;
    
    k = 1;
    for (len = 128; len >= 2; len >>= 1) {
        for (start = 0; start < N; start = j + len) {
            zeta = W[k++]; 
            for (j = start; j < start + len; j++) {
                t = mul_mod(zeta, a[j + len]);
                a[j + len] = mod_q(a[j] - t);
                a[j] = mod_q(a[j] + t);
            }
        }
    }
}

// ====================================================================
// Standard Kyber Gentleman-Sande Butterfly INTT
// ====================================================================
void intt(int16_t *a) {
    int len, start, j, k;
    int16_t zeta, t;
    
    k = 127;
    for (len = 2; len <= 128; len <<= 1) {
        for (start = 0; start < N; start = j + len) {
            zeta = W[k--]; 
            for (j = start; j < start + len; j++) {
                t = a[j];
                a[j] = mod_q(t + a[j + len]);
                
                // FIPS 203 requires subtracting top from bottom
                a[j + len] = mod_q(a[j + len] - t);
                a[j + len] = mul_mod(zeta, a[j + len]);
            }
        }
    }
    
  // Scale by 128^-1 mod Q=3329 in Montgomery domain (3303 * R mod Q = 512)
    for (j = 0; j < N; j++) {
        a[j] = mul_mod(a[j], 512);
    }
}

// ====================================================================
// Standard Kyber Base Multiplication Drop-In Replacement
// ====================================================================
void poly_mul(int16_t *a, int16_t *b, int16_t *res) {
    int16_t a_ntt[N], b_ntt[N];
    
    for(int i = 0; i < N; i++) {
        a_ntt[i] = a[i];
        b_ntt[i] = b[i];
    }
    
    ntt(a_ntt);
    ntt(b_ntt);
    
    for(int i = 0; i < 128; i++) {
        int16_t zeta = odd_powers[bitrev7(i)];
        
        int16_t a0 = a_ntt[2*i];
        int16_t a1 = a_ntt[2*i + 1];
        int16_t b0 = b_ntt[2*i];
        int16_t b1 = b_ntt[2*i + 1];

    // 1. Raw polynomial products in standard domain via Barrett
        int16_t a0_b0 = mod_q((int32_t)a0 * b0);
        int16_t a0_b1 = mod_q((int32_t)a0 * b1);
        int16_t a1_b0 = mod_q((int32_t)a1 * b0);
        int16_t a1_b1 = mod_q((int32_t)a1 * b1);

// 2. mul_mod (Montgomery) is ONLY used for zeta        
        res[2*i]     = mod_q(a0_b0 + mul_mod(a1_b1, zeta));
        res[2*i + 1] = mod_q(a0_b1 + a1_b0);
    }
    
    intt(res);
}



// NTT-domain pointwise ring product (FIPS 203 Algorithm 12, BaseCaseMultiply).
// Both inputs must already be NTT-domain; output is NTT-domain too.

void poly_basemul(int16_t *res, const int16_t *a_hat, const int16_t *b_hat) {
    for (int i = 0; i < 128; i++) {
        // Read directly from the precomputed table
        int16_t zeta = odd_powers_br[i]; 
        
        int16_t a0 = a_hat[2*i], a1 = a_hat[2*i + 1];
        int16_t b0 = b_hat[2*i], b1 = b_hat[2*i + 1];

       // 1. Raw polynomial products in standard domain via Barrett
        int16_t a0_b0 = mod_q((int32_t)a0 * b0);
        int16_t a0_b1 = mod_q((int32_t)a0 * b1);
        int16_t a1_b0 = mod_q((int32_t)a1 * b0);
        int16_t a1_b1 = mod_q((int32_t)a1 * b1);

        // 2. mul_mod (Montgomery) is ONLY used for zeta
        res[2*i]     = mod_q(a0_b0 + mul_mod(a1_b1, zeta));
        res[2*i + 1] = mod_q(a0_b1 + a1_b0);
    }
}

// acc += a_hat * b_hat, all NTT-domain, for building matrix-vector dot products

void poly_basemul_acc(int16_t *acc, const int16_t *a_hat, const int16_t *b_hat) {
    int16_t tmp[N];
    poly_basemul(tmp, a_hat, b_hat);
    for (int i = 0; i < N; i++) acc[i] = mod_q(acc[i] + tmp[i]);
}