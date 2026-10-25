#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "kyber.h"
#include "dma_utils.h"
#include "math_utils.h"
#include "aes.h"
#include "ntt.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "fips202.h"
#include "hardware/structs/systick.h"

// ======================================================================
// 1. WI-FI & ALICE'S CREDENTIALS
// ======================================================================
#define WIFI_SSID "OPPO A54"
#define WIFI_PASSWORD "Abeerkhan28" 
#define ALICE_IP "10.102.142.154"
#define TCP_PORT 4444

// ======================================================================
// 2. GLOBAL VARIABLES
// ======================================================================
uint8_t pk_buffer[800]; // Holds Alice's Matrix A (2048) + Vector t (1024)
uint8_t ct_buffer[1536]; // Holds Bob's Vector u (1024) + Vector v (512)
int pk_bytes_received = 0;

uint8_t shared_key_bob[32]; // The final quantum-proof key
kyber_keypair alice_public; // We only fill the A and t parts!


void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}


// ======================================================================
// 3. TCP CALLBACKS (Event-Driven Networking)
// ======================================================================

// This runs when Alice sends us her Public Key
err_t client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (p == NULL) {
        tcp_close(tpcb);
        return ERR_OK;
    }

    // Copy incoming bytes into our public key buffer
   struct pbuf *q;
   for (q = p; q != NULL; q = q->next) {
     memcpy(&pk_buffer[pk_bytes_received], q->payload, q->len);
     pk_bytes_received += q->len;
   }
     tcp_recved(tpcb, p->tot_len); 
     pbuf_free(p);


// DID WE GET THE WHOLE PUBLIC KEY? (Standard 800 bytes)
    if (pk_bytes_received >= 800) {
        printf("\n[+] Full 800-byte Public Key received from Alice! Unpacking...\n");
        
        // 1. Unpack and Regenerate Matrix A
        
unpack_pk(&alice_public, pk_buffer);

printf("[*] Regenerating Matrix A from seed (SHAKE-128)...\n");
gen_matrix_A(alice_public.A, alice_public.seed_rho);
        
        // 2. ENCAPSULATE (With Timer!)
        printf("[*] Running Encapsulation...\n");
        uint32_t start_time = time_us_32();
        
        // Call encapsulate. It automatically compresses and fills 'ct_buffer'!
        encapsulate(&alice_public, ct_buffer, shared_key_bob);
        
        uint32_t end_time = time_us_32();
        printf("[+] Encapsulation Complete in %lu us.\n", (end_time - start_time));

        // 3. Send the 768-byte Ciphertext back to Alice
        printf("[*] Sending 768-byte Ciphertext back to Alice...\n");
        tcp_write(tpcb, ct_buffer, 768, TCP_WRITE_FLAG_COPY);
        tcp_output(tpcb);
        
        // 4. PROVE AES WORKS ON BOB'S SIDE!
        printf("[+] Shared Secret Generated! First 4 bytes: %02x %02x %02x %02x\n", 
            shared_key_bob[0], shared_key_bob[1], shared_key_bob[2], shared_key_bob[3]);

        
        // ==========================================
        // NEW: SEND A SECURE MESSAGE TO ALICE!
        // ==========================================
        // We use exactly 32 bytes (two 16-byte AES blocks)
        struct AES_ctx ctx;
        uint8_t secret_msg[32] = "top secret code is 99542";
        printf("\n[*] Plaintext to send: '%s'\n", secret_msg);
        
        // Initialize the lock with Bob's Kyber Key
        AES_init_ctx(&ctx, shared_key_bob); 
        
        // Encrypt the text into garbage
        for(int i = 0; i < 32; i += 16) {
            AES_ECB_encrypt(&ctx, &secret_msg[i]);
        }
        
        printf("[*] Sending scrambled bytes over Wi-Fi...\n");
        
        // Send the locked message to Alice
        tcp_write(tpcb, secret_msg, 32, TCP_WRITE_FLAG_COPY);
        tcp_output(tpcb);

        // ==========================================
        // SECURE ZEROIZATION (Defending against memory extraction)
        // ==========================================
        printf("[*] Session complete. Executing Secure Zeroization...\n");
        
        // Use a volatile pointer so the -O3 compiler doesn't skip this!
        volatile uint8_t *p_key = (volatile uint8_t *)shared_key_bob;
        volatile uint8_t *p_msg = (volatile uint8_t *)secret_msg;
        
        for (int i = 0; i < 32; i++) {
            p_key[i] = 0;
            p_msg[i] = 0;
        }
        
        printf("[+] AES Key and Plaintext successfully wiped from RAM.\n");

        pk_bytes_received = 0; // Reset just in case
    }
    return ERR_OK;
}
        
// This runs when we successfully connect to Alice
err_t client_connected(void *arg, struct tcp_pcb *tpcb, err_t err) {
    if (err == ERR_OK) {
        printf("[+] Connected to Alice! Waiting for her Public Key...\n");
        tcp_recv(tpcb, client_recv);
    } else {
        printf("[-] Failed to connect to Alice.\n");
    }
    return err;
}

// ======================================================================
// 4. MAIN SETUP
// ======================================================================
int main() {
    stdio_init_all();
    // NEW: Enable DWT hardware cycle counter
    *(volatile uint32_t*)0xE000EDFC |= 1 << 24; 
    *(volatile uint32_t*)0xE0001000 |= 1;       


    sleep_ms(3000); 
    printf("\n=== Bob (Kyber512 TCP Client) Booting ===\n");

    dma_copy_init();
    init_ntt();

    // 1. Connect to Wi-Fi
    if (cyw43_arch_init_with_country(CYW43_COUNTRY_WORLDWIDE)) {
        printf("[-] Wi-Fi init failed\n");
        return -1;
    }
    cyw43_arch_enable_sta_mode();
    printf("[*] Connecting to %s...\n", WIFI_SSID);
    
    if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
        printf("[-] Failed to connect.\n");
        return -1;
    }
    printf("[+] Connected! Bob's IP: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

    // 2. Connect to Alice
    ip_addr_t alice_ipaddr;
    ipaddr_aton(ALICE_IP, &alice_ipaddr);

    struct tcp_pcb *pcb = tcp_new();
    printf("[*] Reaching out to Alice at %s:%d...\n", ALICE_IP, TCP_PORT);
    tcp_connect(pcb, &alice_ipaddr, TCP_PORT, client_connected);

    // 3. Background Wi-Fi loop
    while (1) {
        cyw43_arch_poll(); 
        sleep_ms(1);
    }

    return 0;
}