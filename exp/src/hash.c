#include "psa/crypto.h"

#include "autoconf.h"

#include <string.h>

psa_status_t psa_hash_compute(psa_algorithm_t alg,
                              const uint8_t * input,
                              size_t input_length,
                              uint8_t * hash,
                              size_t hash_size,
                              size_t * hash_length)
{
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t status;

    if (((status = psa_hash_setup( &operation, alg)) == PSA_SUCCESS) &&
        ((status = psa_hash_update( &operation, input, input_length)) == PSA_SUCCESS) &&
        ((status = psa_hash_finish( &operation, hash, hash_size, hash_length)) == PSA_SUCCESS)) {
            return psa_hash_abort(&operation);
    } else {
        psa_hash_abort(&operation);
        return status;
    }
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
    switch (alg)
    {
#if CONFIG_HAVE_SHA2_256
    case PSA_ALG_SHA_256:
        operation->alg = alg;
        psa_hash_sha256_setup(&operation->ctx.sha256);
        return PSA_SUCCESS;
#endif
    default:
        break;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_update(psa_hash_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length)
{
    switch (operation->alg)
    {
#if CONFIG_HAVE_SHA2_256
    case PSA_ALG_SHA_256:
        return psa_hash_sha256_update(&operation->ctx.sha256, input, input_length);
#endif
    default:
        break;
    }
    return PSA_ERROR_NOT_SUPPORTED;
}

psa_status_t psa_hash_finish(psa_hash_operation_t * operation,
                             uint8_t * hash,
                             size_t hash_size,
                             size_t * hash_length)
{
    size_t actual_hash_length = PSA_HASH_SIZE(operation->alg);

    if(hash_size < actual_hash_length) {
        return PSA_ERROR_BUFFER_TOO_SMALL;
    }
    memset(hash, 0, hash_size);
    *hash_length = actual_hash_length;

    switch (operation->alg)
    {
#if CONFIG_HAVE_SHA2_256
    case PSA_ALG_SHA_256:
        return psa_hash_sha256_finish(&operation->ctx.sha256, hash);
#endif
    default:
        break;
    }
    return PSA_ERROR_NOT_SUPPORTED;
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

