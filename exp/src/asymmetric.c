#include "psa/crypto.h"

psa_status_t psa_asymmetric_sign(psa_key_handle_t handle,
                                 psa_algorithm_t alg,
                                 const uint8_t * hash,
                                 size_t hash_length,
                                 uint8_t * signature,
                                 size_t signature_size,
                                 size_t * signature_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_asymmetric_verify(psa_key_handle_t handle,
                                   psa_algorithm_t alg,
                                   const uint8_t * hash,
                                   size_t hash_length,
                                   const uint8_t * signature,
                                   size_t signature_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_asymmetric_encrypt(psa_key_handle_t handle,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_asymmetric_decrypt(psa_key_handle_t handle,
                                    psa_algorithm_t alg,
                                    const uint8_t * input,
                                    size_t input_length,
                                    const uint8_t * salt,
                                    size_t salt_length,
                                    uint8_t * output,
                                    size_t output_size,
                                    size_t * output_length)
{
    return PSA_SUCCESS;
}

