//
// Created by dkulpa on 17.08.2025.
//

#ifndef MGLIGHTFW_G2_BLELNBASE_H
#define MGLIGHTFW_G2_BLELNBASE_H

#include <Arduino.h>
#include <Preferences.h>
#include <mbedtls/gcm.h>
#include <mbedtls/ecp.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/md.h> // HMAC (HKDF implementujemy ręcznie)
#include "BLELNConnCtx.h"

void hexDump(const char* label, const uint8_t* data, size_t len);

class BLELNBase {
public:
    static const char* SERVICE_UUID;
    static const char* KEYEX_TX_UUID;
    static const char* KEYEX_RX_UUID;
    static const char* DATA_TX_UUID;
    static const char* DATA_RX_UUID;

    static bool rngInitialised;
    static mbedtls_entropy_context entropy;
    static mbedtls_ctr_drbg_context ctr_drbg;

    static void hkdf_sha256(const uint8_t* salt, size_t salt_len,
                            const uint8_t* ikm, size_t ikm_len,
                            const uint8_t* info, size_t info_len,
                            uint8_t* okm, size_t okm_len);

    static void random_bytes(uint8_t* out, size_t len);
    static void load_or_init_psk(Preferences *prefs, uint8_t *g_psk_salt, uint32_t *g_epoch);
    static void rotate_psk(Preferences *prefs, uint8_t *g_psk_salt, uint32_t * g_epoch);
    static void rng_init();

    static bool ecdh_gen(uint8_t pub65[65], mbedtls_ecp_group& g, mbedtls_mpi& d, mbedtls_ecp_point& Q);
    static bool ecdh_shared(const mbedtls_ecp_group& g,const mbedtls_mpi& d,const uint8_t pub65[65],uint8_t out[32]);
    static bool gcm_encrypt(const uint8_t key[32], const uint8_t* plain,size_t plen,const uint8_t* nonce12,const uint8_t* aad,size_t aadLen,std::string& out,uint8_t tag[16]);
};


#endif //MGLIGHTFW_G2_BLELNBASE_H
