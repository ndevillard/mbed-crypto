#include "psa/crypto.h"


psa_status_t psa_aead_encrypt(psa_key_handle_t handle,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * plaintext,
                              size_t plaintext_length,
                              uint8_t * ciphertext,
                              size_t ciphertext_size,
                              size_t * ciphertext_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_decrypt(psa_key_handle_t handle,
                              psa_algorithm_t alg,
                              const uint8_t * nonce,
                              size_t nonce_length,
                              const uint8_t * additional_data,
                              size_t additional_data_length,
                              const uint8_t * ciphertext,
                              size_t ciphertext_length,
                              uint8_t * plaintext,
                              size_t plaintext_size,
                              size_t * plaintext_length)
{
    return PSA_SUCCESS;
}

psa_aead_operation_t psa_aead_operation_init(void)
{
}


psa_status_t psa_aead_encrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_handle_t handle,
                                    psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_decrypt_setup(psa_aead_operation_t * operation,
                                    psa_key_handle_t handle,
                                    psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_generate_nonce(psa_aead_operation_t * operation,
                                     unsigned char * nonce,
                                     size_t nonce_size,
                                     size_t * nonce_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_set_nonce(psa_aead_operation_t * operation,
                                const unsigned char * nonce,
                                size_t nonce_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_set_lengths(psa_aead_operation_t * operation,
                                  size_t ad_length,
                                  size_t plaintext_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_update_ad(psa_aead_operation_t * operation,
                                const uint8_t * input,
                                size_t input_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_update(psa_aead_operation_t * operation,
                             const uint8_t * input,
                             size_t input_length,
                             unsigned char * output,
                             size_t output_size,
                             size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_finish(psa_aead_operation_t * operation,
                             uint8_t * ciphertext,
                             size_t ciphertext_size,
                             size_t * ciphertext_length,
                             uint8_t * tag,
                             size_t tag_size,
                             size_t * tag_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_verify(psa_aead_operation_t * operation,
                             uint8_t * plaintext,
                             size_t plaintext_size,
                             size_t * plaintext_length,
                             const uint8_t * tag,
                             size_t tag_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_aead_abort(psa_aead_operation_t * operation)
{
    return PSA_SUCCESS;
}

