#ifndef _ALT_INTEL_TINYCRYPT_VENDOR_H
#define _ALT_INTEL_TINYCRYPT_VENDOR_H

#include "autoconf.h"

#ifdef CONFIG_INTEL_TINYCRYPT_SHA2_256
#include "tinycrypt/lib/include/tinycrypt/constants.h"
#include "tinycrypt/lib/include/tinycrypt/sha256.h"

typedef struct tc_sha256_state_struct psa_hash_sha256_context_t;

#define psa_hash_sha256_setup(ctx) \
     tc_sha256_init(ctx)

#define psa_hash_sha256_update(ctx, input, input_length) \
     tc_sha256_update(ctx, (const uint8_t *)input, input_length) == TC_CRYPTO_SUCCESS ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;

#define psa_hash_sha256_finish(ctx, output) \
     tc_sha256_final((uint8_t *)output, ctx) == TC_CRYPTO_SUCCESS ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;

#endif

#endif