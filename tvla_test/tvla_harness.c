// tvla_harness.c
//
// On-chip TVLA trace collection for decapsulate(), targeting the concern:
// "remote/network timing cannot reveal a leak of a few cycles."
// This measures cycles directly on the RP2040 core via SysTick in
// free-running mode (Cortex-M0+ has no DWT cycle counter), with no
// network, DMA, or peripheral path in the timed region.
//
// Methodology: standard non-specific TVLA.
//   Class A ("fixed")  = one pre-encapsulated, valid ciphertext, reused
//                        every trial.
//   Class B ("random") = a fresh uniformly random 768-byte buffer every
//                        trial (will trigger implicit rejection almost
//                        always -- also stresses the CMOV branch).
// Labels are shuffled once up front and interleaved trial-to-trial to
// avoid drift confounds. Output is streamed as "class,cycles\n" over
// USB CDC so it can be captured to a file and sliced into independent
// repeated batches on the host side.
//
// Build: add this file to your existing Pico-SDK project and call
// tvla_run() from main() instead of (or alongside, behind a build flag)
// normal firmware operation.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "pico/stdlib.h"
#include "hardware/sync.h"
#include "kyber.h"

// ====================================================================
// Cycle counter: SysTick in free-running mode, processor clock source.
// ====================================================================
#define SYST_CSR  (*(volatile uint32_t *)0xE000E010u)
#define SYST_RVR  (*(volatile uint32_t *)0xE000E014u)
#define SYST_CVR  (*(volatile uint32_t *)0xE000E018u)

#define SYST_CSR_ENABLE    (1u << 0)
#define SYST_CSR_CLKSOURCE (1u << 2)   // 1 = processor clock (not /8)
#define SYST_RELOAD_MAX    0x00FFFFFFu // 24-bit counter

static inline void cyclecnt_init(void) {
    SYST_RVR = SYST_RELOAD_MAX;
    SYST_CVR = 0;                                // any write clears it
    SYST_CSR = SYST_CSR_ENABLE | SYST_CSR_CLKSOURCE; // TICKINT left off: no ISR jitter
}

static inline uint32_t cyclecnt_read(void) {
    return SYST_CVR; // counts DOWN from RELOAD to 0, then wraps
}

// SysTick counts down, so start_val > end_val for the common case;
// handle a single wrap (decapsulate() takes nowhere near 2^24 cycles).
static inline uint32_t elapsed_cycles(uint32_t start_val, uint32_t end_val) {
    if (end_val <= start_val) return start_val - end_val;
    return start_val + (SYST_RELOAD_MAX + 1u - end_val);
}

// ====================================================================
// Timed decapsulate() call -- per-segment bisection version. Calls
// decapsulate_instrumented() (see decapsulate_instrumented.c) which is a
// functional clone of decapsulate() with 5 internal checkpoints, so we
// can find WHICH segment leaks instead of just knowing the whole
// function does.
// ====================================================================
extern void decapsulate_instrumented(kyber_keypair *kp, uint8_t *ct, uint8_t *shared_key,
                                      uint32_t *segment_cycles);

#define N_SEGMENTS 5

static void time_decapsulate_segmented(kyber_keypair *kp, const uint8_t *ct,
                                        uint8_t *out_k, uint32_t *segs) {
    uint32_t irq_state = save_and_disable_interrupts();
    decapsulate_instrumented(kp, (uint8_t *)ct, out_k, segs);
    restore_interrupts(irq_state);
}

// ====================================================================
// Small non-crypto PRNG (xorshift32) purely to shuffle the A/B label
// sequence -- NOT used for any secret material. Seed once from the
// hardware RNG path already in your build (or any fixed seed is fine;
// the shuffle order isn't security-sensitive, only the class-B
// ciphertext content is, and that still comes from your real RNG).
// ====================================================================
static uint32_t xs_state = 0x9E3779B9u;
static inline uint32_t xorshift32(void) {
    uint32_t x = xs_state;
    x ^= x << 13; x ^= x >> 17; x ^= x << 5;
    return xs_state = x;
}

static void shuffle_labels(uint8_t *labels, uint32_t n) {
    for (uint32_t i = n - 1; i > 0; i--) {
        uint32_t j = xorshift32() % (i + 1);
        uint8_t tmp = labels[i]; labels[i] = labels[j]; labels[j] = tmp;
    }
}

// ====================================================================
// Main TVLA collection loop.
// n_per_class: number of traces per class (pass >= 10000 per the
// reviewer's minimum; more is better).
// ====================================================================
void tvla_run(uint32_t n_per_class) {
    stdio_init_all();
    cyclecnt_init();

    // --- Set up one real key pair and one valid ciphertext (Class A) ---
    kyber_keypair kp;
    keygen(&kp);

    uint8_t ct_fixed[768], k_tmp[32];
    encapsulate(&kp, ct_fixed, k_tmp); // Class A ciphertext: genuinely valid

    // --- Build and shuffle the interleaved label sequence ---
    uint32_t total = 2u * n_per_class;
    uint8_t *labels = malloc(total);
    for (uint32_t i = 0; i < n_per_class; i++) { labels[i] = 'A'; labels[n_per_class + i] = 'B'; }
    shuffle_labels(labels, total);

    printf("# TVLA on-chip per-segment cycle trace, n_per_class=%lu\n", (unsigned long)n_per_class);
    printf("class,seg_unpack,seg_msgrecover,seg_keyderive,seg_reencrypt,seg_cmov,total\n");

    uint8_t ct_rand[768];
    uint8_t out_k[32];
    uint32_t segs[N_SEGMENTS];

    for (uint32_t i = 0; i < total; i++) {
        // ALWAYS generate a random ciphertext to ensure identical XIP cache 
        // and branch predictor states prior to entering the timed region.
        randombytes(ct_rand, sizeof(ct_rand));
        
        // Select which ciphertext to feed based on the label
        uint8_t *ct_ptr = (labels[i] == 'A') ? ct_fixed : ct_rand;
        
        time_decapsulate_segmented(&kp, ct_ptr, out_k, segs);
        
        uint32_t total_cycles = segs[0] + segs[1] + segs[2] + segs[3] + segs[4];
        printf("%c,%lu,%lu,%lu,%lu,%lu,%lu\n", labels[i],
               (unsigned long)segs[0], (unsigned long)segs[1], (unsigned long)segs[2],
               (unsigned long)segs[3], (unsigned long)segs[4], (unsigned long)total_cycles);
    }

    free(labels);
    printf("# TVLA collection complete\n");
}

// Example entry point -- wire this into your existing main() as
// appropriate for your build (e.g. behind a TVLA_MODE compile flag so
// normal firmware operation is unaffected).
#ifdef TVLA_STANDALONE_MAIN
int main(void) {
    tvla_run(15000);
    while (1) { tight_loop_contents(); }
}
#endif
