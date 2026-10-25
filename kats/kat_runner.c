#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "cJSON.h"
#include "kyber.h"
#include "ntt.h"

// ====================================================================
// DETERMINISTIC RNG MOCK
// ====================================================================
static const uint8_t *kat_bytes;
static size_t kat_len;
static size_t kat_pos;

void kat_load(const uint8_t *buf, size_t len) {
    kat_bytes = buf;
    kat_len = len;
    kat_pos = 0;
}

void randombytes(uint8_t *out, size_t outlen) {
    if (kat_pos + outlen > kat_len) {
        printf("[-] FATAL: RNG Buffer Underrun!\n");
        exit(1);
    }
    memcpy(out, kat_bytes + kat_pos, outlen);
    kat_pos += outlen;
}

// ====================================================================
// UTILITIES
// ====================================================================
void hex2bytes(const char *hex, uint8_t *out) {
    size_t len = strlen(hex);
    for (size_t i = 0; i < len; i += 2) {
        unsigned int byte;
        sscanf(&hex[i], "%2x", &byte);
        out[i / 2] = (uint8_t)byte;
    }
}

char* read_file(const char *filename) {
    FILE *f = fopen(filename, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long length = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buffer = malloc(length + 1);
    fread(buffer, 1, length, f);
    buffer[length] = '\0';
    fclose(f);
    return buffer;
}

// ====================================================================
// TEST RUNNERS
// ====================================================================
void run_keygen_kat(cJSON *tests) {
    cJSON *test;
    int passed = 0, failed = 0;

    cJSON_ArrayForEach(test, tests) {
        uint8_t d[32], z[32], rng_buf[64];
        uint8_t expected_ek[800], expected_dk[1632];
        uint8_t actual_ek[800], actual_dk[1632];

        hex2bytes(cJSON_GetObjectItem(test, "d")->valuestring, d);
        hex2bytes(cJSON_GetObjectItem(test, "z")->valuestring, z);
        hex2bytes(cJSON_GetObjectItem(test, "ek")->valuestring, expected_ek);
        hex2bytes(cJSON_GetObjectItem(test, "dk")->valuestring, expected_dk);

        // KeyGen expects d then z
        memcpy(rng_buf, d, 32);
        memcpy(rng_buf + 32, z, 32);
        kat_load(rng_buf, 64);

        kyber_keypair kp;
        keygen(&kp);
        pack_pk(actual_ek, kp.t, kp.seed_rho);
        pack_sk(actual_dk, &kp);

        if (memcmp(expected_ek, actual_ek, 800) == 0 && memcmp(expected_dk, actual_dk, 1632) == 0) {
            passed++;
        } else {
            failed++;
            printf("[-] KeyGen TCId %d FAILED\n", cJSON_GetObjectItem(test, "tcId")->valueint);
        }
    }
    printf("[*] KeyGen: %d Passed, %d Failed\n", passed, failed);
}

void run_encap_kat(cJSON *tests) {
    cJSON *test;
    int passed = 0, failed = 0;

    cJSON_ArrayForEach(test, tests) {
        uint8_t ek[800], m[32];
        uint8_t expected_c[768], expected_k[32];
        uint8_t actual_c[768], actual_k[32];

        hex2bytes(cJSON_GetObjectItem(test, "ek")->valuestring, ek);
        hex2bytes(cJSON_GetObjectItem(test, "m")->valuestring, m);
        hex2bytes(cJSON_GetObjectItem(test, "c")->valuestring, expected_c);
        hex2bytes(cJSON_GetObjectItem(test, "k")->valuestring, expected_k);

        kyber_keypair kp;
        unpack_pk(&kp, ek);

        // Encapsulation consumes m
        kat_load(m, 32);
        encapsulate(&kp, actual_c, actual_k);

        if (memcmp(expected_c, actual_c, 768) == 0 && memcmp(expected_k, actual_k, 32) == 0) {
            passed++;
        } else {
            failed++;
            printf("[-] Encap TCId %d FAILED\n", cJSON_GetObjectItem(test, "tcId")->valueint);
        }
    }
    printf("[*] Encapsulation: %d Passed, %d Failed\n", passed, failed);
}

void run_decap_kat(cJSON *tests) {
    cJSON *test;
    int passed = 0, failed = 0;

    cJSON_ArrayForEach(test, tests) {
        uint8_t dk[1632], c[768];
        uint8_t expected_k[32], actual_k[32];

        hex2bytes(cJSON_GetObjectItem(test, "dk")->valuestring, dk);
        hex2bytes(cJSON_GetObjectItem(test, "c")->valuestring, c);
        hex2bytes(cJSON_GetObjectItem(test, "k")->valuestring, expected_k);

        kyber_keypair kp;
        unpack_sk(&kp, dk);
        decapsulate(&kp, c, actual_k);

        if (memcmp(expected_k, actual_k, 32) == 0) {
            passed++;
        } else {
            failed++;
            printf("[-] Decap TCId %d FAILED\n", cJSON_GetObjectItem(test, "tcId")->valueint);
        }
    }
    printf("[*] Decapsulation: %d Passed, %d Failed\n", passed, failed);
}

// ML-KEM.KeyGen_internal / Encaps_internal input validation checks
// (ACVP "encapsulationKeyCheck" / "decapsulationKeyCheck" test groups).
// These feed deliberately malformed ek/dk and expect a specific
// accept/reject outcome, exercising unpack_pk's modulus check.
void run_encap_key_check_kat(cJSON *tests) {
    cJSON *test;
    int passed = 0, failed = 0;

    cJSON_ArrayForEach(test, tests) {
        uint8_t ek[800];
        hex2bytes(cJSON_GetObjectItem(test, "ek")->valuestring, ek);

        cJSON *test_passed_flag = cJSON_GetObjectItem(test, "testPassed");
        int expected_valid = cJSON_IsTrue(test_passed_flag);

        kyber_keypair kp;
        int result = unpack_pk(&kp, ek);
        int is_valid = (result == 0); // 0 means success, -1 means failure

        if (expected_valid == is_valid) {
            passed++;
        } else {
            failed++;
            printf("[-] EncapKeyCheck TCId %d FAILED (Expected %d, got %d)\n",
                   cJSON_GetObjectItem(test, "tcId")->valueint, expected_valid, is_valid);
        }
    }
    printf("[*] Encapsulation Key Check: %d Passed, %d Failed\n", passed, failed);
}

void run_decap_key_check_kat(cJSON *tests) {
    cJSON *test;
    int passed = 0, failed = 0;

    cJSON_ArrayForEach(test, tests) {
        uint8_t dk[1632];
        hex2bytes(cJSON_GetObjectItem(test, "dk")->valuestring, dk);

        cJSON *test_passed_flag = cJSON_GetObjectItem(test, "testPassed");
        int expected_valid = cJSON_IsTrue(test_passed_flag);

        kyber_keypair kp;
        int result = unpack_sk(&kp, dk);
        int is_valid = (result == 0); // 0 means success, -1 means failure

        if (expected_valid == is_valid) {
            passed++;
        } else {
            failed++;
            printf("[-] DecapKeyCheck TCId %d FAILED (Expected %d, got %d)\n",
                   cJSON_GetObjectItem(test, "tcId")->valueint, expected_valid, is_valid);
        }
    }
    printf("[*] Decapsulation Key Check: %d Passed, %d Failed\n", passed, failed);
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <kat.json>\n", argv[0]);
        return 1;
    }

    // CRITICAL FIX: Initialize NTT Twiddle Factors before any cryptography runs
    init_ntt();

    char *json_data = read_file(argv[1]);
    if (!json_data) {
        printf("[-] Failed to read JSON file.\n");
        return 1;
    }

    cJSON *root = cJSON_Parse(json_data);
    if (!root) {
        printf("[-] Failed to parse JSON data.\n");
        free(json_data);
        return 1;
    }

    cJSON *mode = cJSON_GetObjectItemCaseSensitive(root, "mode");
    cJSON *testGroups = cJSON_GetObjectItemCaseSensitive(root, "testGroups");
    cJSON *group;

    printf("\n--- Running NIST KAT: %s ---\n", mode->valuestring);

    cJSON_ArrayForEach(group, testGroups) {
        if (strcmp(mode->valuestring, "keyGen") == 0) {
            run_keygen_kat(cJSON_GetObjectItem(group, "tests"));
        }
        else if (strcmp(mode->valuestring, "encapDecap") == 0) {
            cJSON *func = cJSON_GetObjectItem(group, "function");
            if (strcmp(func->valuestring, "encapsulation") == 0) {
                run_encap_kat(cJSON_GetObjectItem(group, "tests"));
            }
            else if (strcmp(func->valuestring, "decapsulation") == 0) {
                run_decap_kat(cJSON_GetObjectItem(group, "tests"));
            }
            else if (strcmp(func->valuestring, "encapsulationKeyCheck") == 0) {
                run_encap_key_check_kat(cJSON_GetObjectItem(group, "tests"));
            }
            else if (strcmp(func->valuestring, "decapsulationKeyCheck") == 0) {
                run_decap_key_check_kat(cJSON_GetObjectItem(group, "tests"));
            }
        }
    }

    cJSON_Delete(root);
    free(json_data);
    return 0;
}
