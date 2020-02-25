#ifndef _ALT_ARM_MBEDTLS_VENDOR_H
#define _ALT_ARM_MBEDTLS_VENDOR_H

#include "autoconf.h"

#ifdef CONFIG_ARM_MBEDTLS_SHA2_256
#include "sha256.h"

typedef arm_mbedtls_sha256_context psa_hash_sha256_context_t;

#define psa_hash_sha256_setup(ctx) \
     arm_mbedtls_sha256_setup(ctx, 0)

#define psa_hash_sha256_update(ctx, input, input_length) \
     arm_mbedtls_sha256_update(ctx, (const unsigned char *)input, input_length) == 0 ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;

#define psa_hash_sha256_finish(ctx, output) \
     arm_mbedtls_sha256_finish(ctx, (unsigned char *)output) == 0 ? PSA_SUCCESS : PSA_ERROR_GENERIC_ERROR;

#endif

#endif