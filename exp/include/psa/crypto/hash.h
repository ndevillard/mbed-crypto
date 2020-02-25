#ifndef _PSA_CRYPTO_HASH_H_
#define _PSA_CRYPTO_HASH_H_

#include <psa/crypto.h>
#include "autoconf.h"
#include "vendors.h"

typedef struct psa_hash_operation_s psa_hash_operation_t;

struct psa_hash_operation_s {
    psa_algorithm_t alg;
    union {
#ifdef CONFIG_HAVE_SHA2_256
        psa_hash_sha256_context_t sha256;
#endif
    } ctx;    
};

#define PSA_ALG_SHA_224  ((psa_algorithm_t)0x01000008)
#define PSA_ALG_SHA_256  ((psa_algorithm_t)0x01000009)
#define PSA_ALG_SHA_384  ((psa_algorithm_t)0x0100000a)
#define PSA_ALG_SHA_512  ((psa_algorithm_t)0x0100000b)
#define PSA_ALG_SHA_512_224  ((psa_algorithm_t)0x0100000c)
#define PSA_ALG_SHA_512_256  ((psa_algorithm_t)0x0100000d)
#define PSA_ALG_SHA3_224  ((psa_algorithm_t)0x01000010)
#define PSA_ALG_SHA3_256  ((psa_algorithm_t)0x01000011)
#define PSA_ALG_SHA3_384  ((psa_algorithm_t)0x01000012)
#define PSA_ALG_SHA3_512  ((psa_algorithm_t)0x01000013)
#define PSA_ALG_ANY_HASH  ((psa_algorithm_t)0x010000ff)

#define PSA_ALG_IS_HASH(alg)  /* <IMPDEF expression> */

#define PSA_HASH_SIZE(alg)  \
    ((alg == PSA_ALG_SHA_256) ? 32 : -1) \
        /* <IMPDEF expression> */
#define PSA_HASH_MAX_SIZE  /* <IMPDEF constant> */

#define PSA_HASH_OPERATION_INIT  { 0 } \
/* <IMPDEF constant> */

psa_status_t psa_hash_compute(
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    uint8_t * hash,
    size_t hash_size,
    size_t * hash_length);

psa_status_t psa_hash_compare(
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    const uint8_t * hash,
    const size_t hash_length);

psa_hash_operation_t psa_hash_operation_init(void);

psa_status_t psa_hash_setup(
    psa_hash_operation_t * operation,
    psa_algorithm_t alg);

psa_status_t psa_hash_update(
    psa_hash_operation_t * operation,
    const uint8_t * input,
    size_t input_length);

psa_status_t psa_hash_finish(
    psa_hash_operation_t * operation,
    uint8_t * hash,
    size_t hash_size,
    size_t * hash_length);

psa_status_t psa_hash_verify(
    psa_hash_operation_t * operation,
    const uint8_t * hash,
    size_t hash_length);

psa_status_t psa_hash_abort(psa_hash_operation_t * operation);

psa_status_t psa_hash_clone(
    const psa_hash_operation_t * source_operation,
    psa_hash_operation_t * target_operation);

#endif