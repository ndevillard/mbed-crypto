#include "psa/crypto.h"

#include "autoconf.h"

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_compare(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              const uint8_t * hash,
                              const size_t hash_length)
{
    return PSA_SUCCESS;
}

psa_hash_operation_t psa_hash_operation_init(void)
{
    psa_hash_operation_t r;
    return r;
}

psa_status_t psa_hash_setup(psa_hash_operation_t * operation,
                            psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_verify(psa_hash_operation_t * operation,
                             const uint8_t * hash,
                             size_t hash_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_abort(psa_hash_operation_t * operation)
{
    return PSA_SUCCESS;
}

psa_status_t psa_hash_clone(const psa_hash_operation_t * source_operation,
                            psa_hash_operation_t * target_operation)
{
    return PSA_SUCCESS;
}

