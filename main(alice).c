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
// 1. WI-FI CREDENTIALS
// ======================================================================
#define WIFI_SSID "OPPO A54"
#define WIFI_PASSWORD "Abeerkhan28"
#define TCP_PORT 4444

// ======================================================================
// 2. GLOBAL VARIABLES
// ======================================================================
int session_state = 0; // 0 = Kyber Handshake, 1 = Secure AES Stream
kyber_keypair alice;

uint8_t pk_buffer[800]; // Holds Matrix A (2048) + Vector t (1024)
uint8_t ct_buffer[2000]; // Holds Bob's Vector u (1024) + Vector v (512)
int ct_bytes_received = 0;

uint8_t shared_key_alice[32]; // The final quantum-proof key


// ======================================================================
// 3. PACKING / UNPACKING HELPERS
// ======================================================================
void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

// ======================================================================
// 4. TCP CALLBACKS (Event-Driven Networking)
// ======================================================================

// This runs when Bob sends us data
err_t server_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (p == NULL) {
        tcp_close(tpcb);
        session_state = 0;
        return ERR_OK;
    }

    // STATE 0: DOING THE KYBER HANDSHAKE
    if (session_state == 0) {
        struct pbuf *q;
        for (q = p; q != NULL; q = q->next) {
            memcpy(&ct_buffer[ct_bytes_received], q->payload, q->len);
            ct_bytes_received += q->len;
        }

        if (ct_bytes_received >= 768) {
            printf("\n[+] Full Ciphertext received! Decapsulating...\n");

            printf("------------------------------------\n");

  
     dma_start_power_masking();

     absolute_time_t start_time = get_absolute_time(); 
            
     decapsulate(&alice, ct_buffer, shared_key_alice);      
    
     absolute_time_t end_time = get_absolute_time();
  
     dma_stop_power_masking();     

     int64_t decap_time = absolute_time_diff_us(start_time, end_time);

     
            
            printf("[+] Decapsulation Complete in %lld us.\n", decap_time);
            // -----------------------
            
            printf("[+] Shared Secret Recovered! First 4 bytes: %02x %02x %02x %02x\n", 
                shared_key_alice[0], shared_key_alice[1], shared_key_alice[2], shared_key_alice[3]);

            session_state = 1; 
            printf("[+] Handshake Complete. Switching to Secure AES Mode...\n");

            // ==========================================
            // NEW: CHECK FOR A MASHED PACKET!
            // If the router merged them, the AES message is sitting 
            // safely in the buffer right after the 1536 Kyber bytes.
            // ==========================================
            if (ct_bytes_received > 768) {
                uint8_t encrypted_msg[32];
                memcpy(encrypted_msg, &ct_buffer[768], 32); 
                
                struct AES_ctx ctx;
                AES_init_ctx(&ctx, shared_key_alice); 
                for(int i = 0; i < 32; i += 16) {
                    AES_ECB_decrypt(&ctx, &encrypted_msg[i]);
                }
                printf("\n[🔒 -> 🔓] SECURE MESSAGE RECEIVED: %s\n", encrypted_msg);
            }
            
            ct_bytes_received = 0; 
        }
    } 
    
    // STATE 1: STANDARD SEPARATE PACKET
    else if (session_state == 1) {
        uint8_t encrypted_msg[32];
        memset(encrypted_msg, 0, 32);
        memcpy(encrypted_msg, p->payload, p->len > 32 ? 32 : p->len);
        
        struct AES_ctx ctx;
        AES_init_ctx(&ctx, shared_key_alice); 
        for(int i = 0; i < 32; i += 16) {
            AES_ECB_decrypt(&ctx, &encrypted_msg[i]);
        }
        printf("\n[🔒 -> 🔓] SECURE MESSAGE RECEIVED: %s\n", encrypted_msg);
        // ==========================================
        // SECURE ZEROIZATION (Defending against memory extraction)
        // ==========================================
        printf("[*] Message read. Executing Secure Zeroization...\n");
        
        volatile uint8_t *p_key = (volatile uint8_t *)shared_key_alice;
        volatile uint8_t *p_msg = (volatile uint8_t *)encrypted_msg;
        
        for (int i = 0; i < 32; i++) {
            p_key[i] = 0;
            p_msg[i] = 0;
        }
        
        printf("[+] AES Key and Plaintext successfully wiped from RAM.\n");
        
        // Reset state so Alice can accept a new connection safely
        session_state = 0; 
    }

    tcp_recved(tpcb, p->tot_len);
    pbuf_free(p);
    return ERR_OK;
}

// This runs when Bob initially connects to us
err_t server_accept(void *arg, struct tcp_pcb *newpcb, err_t err) {
    printf("\n[+] Bob connected! Sending Kyber512 Public Key...\n");
    
    // Set up the receive callback
    tcp_recv(newpcb, server_recv);
    
    // Send the 800 bytes (Matrix A + Vector t)
    err_t write_err = tcp_write(newpcb, pk_buffer, sizeof(pk_buffer), 0);
    tcp_output(newpcb); // Push the data out immediately
    
    if(write_err == ERR_OK) {
        printf("[+] Public Key sent over Wi-Fi successfully!\n");
    } else {
        printf("[-] Error sending public key.\n");
    }
    return ERR_OK;
}

// ======================================================================
// 5. MAIN SETUP
// ======================================================================
int main() {
    stdio_init_all();
// NEW: Enable DWT hardware cycle counter
    *(volatile uint32_t*)0xE000EDFC |= 1 << 24; 
    *(volatile uint32_t*)0xE0001000 |= 1;
    sleep_ms(3000); // Wait for serial
    printf("\n=== Alice (Kyber512 TCP Server) Booting ===\n");

    // Initialize DMA and NTT Math Arrays
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
    
    // Print Alice's IP Address
    printf("[+] Connected! Alice's IP: %s\n", ip4addr_ntoa(netif_ip4_addr(netif_list)));

    
    // 2. Generate the Kyber Matrices (Only need to do this once for the server demo)
    printf("[*] Generating Kyber512 Matrices...\n");
    absolute_time_t kg_start = get_absolute_time(); 
    
    // Run the key generation
    keygen(&alice);
    
    // Stop the timer
    absolute_time_t kg_end = get_absolute_time();

   // Calculate the difference in microseconds
    int64_t keygen_time = absolute_time_diff_us(kg_start, kg_end);
    
    // Print the result in microseconds
    printf("[+] KeyGen Time: %lld us \n", keygen_time);

    pack_pk(pk_buffer, alice.t, alice.seed_rho);
    printf("[+] Keygen complete. Packed size: %d bytes\n", sizeof(pk_buffer));

    // 3. Setup TCP Server on Port 4444
    struct tcp_pcb *pcb = tcp_new();
    tcp_bind(pcb, IP_ADDR_ANY, TCP_PORT);
    pcb = tcp_listen(pcb);
    tcp_accept(pcb, server_accept);
    
    printf("[+] Alice is listening on port %d... Waiting for Bob.\n", TCP_PORT);

    // 4. Background Wi-Fi loop
    while (1) {
        cyw43_arch_poll(); // Keep Wi-Fi alive
        sleep_ms(1);
    }

    return 0;
}