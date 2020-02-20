#include "psa/crypto.h"


psa_status_t psa_cipher_encrypt(psa_key_handle_t handle,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt(psa_key_handle_t handle,
                                psa_algorithm_t alg,
                                const uint8_t * input,
                                size_t input_length,
                                uint8_t * output,
                                size_t output_size,
                                size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_cipher_operation_t psa_cipher_operation_init(void)
{
    psa_cipher_operation_t r;
    return r;
}

psa_status_t psa_cipher_encrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_handle_t handle,
                                      psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_decrypt_setup(psa_cipher_operation_t * operation,
                                      psa_key_handle_t handle,
                                      psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_generate_iv(psa_cipher_operation_t * operation,
                                    unsigned char * iv,
                                    size_t iv_size,
                                    size_t * iv_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_set_iv(psa_cipher_operation_t * operation,
                               const unsigned char * iv,
                               size_t iv_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_update(psa_cipher_operation_t * operation,
                               const uint8_t * input,
                               size_t input_length,
                               unsigned char * output,
                               size_t output_size,
                               size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_finish(psa_cipher_operation_t * operation,
                               uint8_t * output,
                               size_t output_size,
                               size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_cipher_abort(psa_cipher_operation_t * operation)
{
    return PSA_SUCCESS;
}
