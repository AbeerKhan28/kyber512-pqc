# pqc-kyber512-rp2350
**Resource-Efficient ML-KEM-512 (Kyber-512) Implementation on Raspberry Pi Pico 2 W**

This repository contains a high-performance, bare-metal implementation of the **ML-KEM-512 (Kyber-512)** Post-Quantum Cryptographic (PQC) algorithm, specifically optimized for the ARM Cortex-M33 architecture on the Raspberry Pi Pico 2 W (RP2350). 

Designed as a companion repository for our academic research, this project demonstrates a secure, quantum-resistant key exchange between two networked IoT nodes (Alice and Bob) over Wi-Fi. It integrates constant-time mathematical reductions, global SRAM buffer management, payload compression, and formal side-channel evaluation tools.

## 🚀 Key Features
*   **FIPS 203 Compliant:** Full mathematical implementation of NIST's finalized ML-KEM-512 standard, validated locally against official Cryptographic Algorithm Validation Program (CAVP) Known Answer Tests (KATs).
*   **Networked IoT Ready:** Real-time peer-to-peer key exchange via TCP/IP utilizing the `lwIP` stack and CYW43 Wi-Fi firmware.
*   **Constant-Time Execution:** Division-free, branchless Barrett and Montgomery modular reductions engineered to thwart timing side channels.
*   **TVLA Verified:** Side-channel leakage formally assessed via ISO/IEC 17825 Welch's t-test methodology ($|t| < 4.5$) using on-chip `SysTick` hardware counters.
*   **Physical Security:** Integrated DMA-based noise generation to mask CPU power signatures during sensitive polynomial operations.

## 📂 File Structure

**Core Cryptography & Network Application:**
*   `main(alice).c`: **TCP Server.** Handles KeyGen, sends Public Key, receives Ciphertext, and Decapsulates.
*   `main(bob).c`: **TCP Client.** Receives Public Key, performs Encapsulation, and sends Ciphertext.
*   `kyber.c` / `.h`: Core ML-KEM-512 logic (KeyGen, Encaps, Decaps).
*   `aes.c` / `.h`: AES-256 implementation for post-handshake secure data streaming.
*   `ntt.c` / `.h`: Optimized Number Theoretic Transform (NTT) for fast polynomial multiplication.
*   `dma_utils.c` / `.h`: Hardware-level DMA configurations for continuous bus masking.
*   `math_utils.c` / `.h`: Mathematical helper functions (Barrett/Montgomery).
*   `fips202.c` / `.h`: SHA-3 and SHAKE functions required for Kyber hashing.
*   `lwipopts.h`: Optimized configuration for the `lwIP` network stack on the RP2350.

**NIST CAVP Validation (KATs):**
*   `kat_runner.c`: Desktop-compiled C harness to run deterministic KAT vectors.
*   `ml_kem_512_keygen_kat.json`: Official NIST test vectors for Key Generation.
*   `ml_kem_512_encapdecap_kat.json`: Official NIST test vectors for Encapsulation/Decapsulation and key validation.
*   `cJSON.c` / `.h`: Lightweight JSON parser for the KAT harness.

**Side-Channel & TVLA Evaluation:**
*   `tvla_harness.c`: On-chip test harness utilizing the Cortex-M33 24-bit `SysTick` counter.
*   `decapsulate_instrumented.c`: A segment-bisected clone of `decapsulate()` to localize timing leakage.
*   `capture.py`: Host-side serial script to capture hardware cycle traces.
*   `tvla_analyze1.py`: Statistical analysis script to compute Welch's t-test ($t$-statistic).

## 🛠️ Setup & Build Instructions (IoT Deployment)

**Hardware:** 2x Raspberry Pi Pico 2 W boards.
**Software:** Raspberry Pi Pico SDK, ARM GCC Toolchain (MinGW or Unix).

1.  **Initialize SDK:** Ensure your `PICO_SDK_PATH` environment variable is set.
2.  **Configure Network:** Update the `WIFI_SSID` and `WIFI_PASSWORD` macros inside `main(alice).c` and `main(bob).c`.
3.  **Build:**
    ```bash
    mkdir build && cd build
    cmake -G "MinGW Makefiles" ..
    mingw32-make
    ```
4.  **Deploy:** Flash `alice.uf2` to the Server Pico and `bob.uf2` to the Client Pico.

## 📊 Performance Benchmarks

Our `-O3` bare-metal C implementation was benchmarked on the RP2350 (Cortex-M33 @ 150 MHz). Execution latencies exclude TCP/IP network overhead to isolate raw cryptographic efficiency.

| Operation | Execution Time (ms) | CPU Clock Cycles |
| :--- | :--- | :--- |
| **Key Generation** | 7.88 ms | 1,183,350 |
| **Encapsulation** | 6.42 ms | 963,300 |
| **Decapsulation** | 8.29 ms | 1,244,250 |


## 🔒 NIST CAVP Known Answer Tests (KATs)

To guarantee mathematical parity with the NIST FIPS 203 standard, the cryptographic core can be compiled on a desktop environment and tested deterministically against the official JSON vectors.

**To run the tests:**
```bash
# 1. Compile the testing harness (Requires GCC)
gcc -O3 -DKAT_TEST kat_runner.c kyber.c ntt.c math_utils.c fips202.c cJSON.c -o kat_runner

# 2. Run Key Generation Tests
./kat_runner ml_kem_512_keygen_kat.json

# 3. Run Encapsulation, Decapsulation, and Rejection Tests
./kat_runner ml_kem_512_encapdecap_kat.json
```
*Note: Compiling with `-DKAT_TEST` seamlessly reroutes the hardware TRNG calls (`randombytes()`) to intercept the static seeds provided by the JSON files.*

## 🛡️ Advanced Security Testing

For researchers interested in verifying the Side-Channel resistance, we provide dedicated testing frameworks.

### 1. Test Vector Leakage Assessment (TVLA)
This project includes a formal non-specific TVLA suite based on ISO/IEC 17825 testing principles. It utilizes the RP2350's `SysTick` timer in free-running mode with disabled interrupts to capture cycle-accurate execution times of the `decapsulate()` routine, completely avoiding network and DMA jitter.

**How to run the evaluation:**
1.  **Compile & Flash:** Include `tvla_harness.c` and `decapsulate_instrumented.c` in your CMake build. Call `tvla_run(15000)` from `main()`.
2.  **Capture Traces:** Connect the Pico to your PC and run the capture script:
    ```bash
    python capture.py
    ```
    *This will interleave Class A (fixed valid ciphertext) and Class B (uniform random ciphertext) inputs and stream the cycle counts to `trace.csv`.*
3.  **Analyze Data:** Run the statistical analysis script to compute the Welch's t-test over the dataset ($N > 28,000$ traces):
    ```bash
    python tvla_analyze1.py trace.csv --plot
    ```
    *A passing result (constant-time execution) will yield a t-statistic strictly bounded by $|t| < 4.5$ across all independent segments.*
