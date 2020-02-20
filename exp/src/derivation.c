#include "psa/crypto.h"


psa_key_derivation_operation_t psa_key_derivation_operation_init(void)
{
    psa_key_derivation_operation_t r;
    return r;
}

psa_status_t psa_key_derivation_setup(psa_key_derivation_operation_t * operation,
                                      psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_get_capacity(const psa_key_derivation_operation_t * operation,
                                             size_t * capacity)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_set_capacity(psa_key_derivation_operation_t * operation,
                                             size_t capacity)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_bytes(psa_key_derivation_operation_t * operation,
                                            psa_key_derivation_step_t step,
                                            const uint8_t * data,
                                            size_t data_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_input_key(psa_key_derivation_operation_t * operation,
                                          psa_key_derivation_step_t step,
                                          psa_key_handle_t handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_key_agreement(psa_key_derivation_operation_t * operation,
                                              psa_key_derivation_step_t step,
                                              psa_key_handle_t private_key,
                                              const uint8_t * peer_key,
                                              size_t peer_key_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_output_bytes(psa_key_derivation_operation_t * operation,
                                             uint8_t * output,
                                             size_t output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_output_key(const psa_key_attributes_t * attributes,
                                           psa_key_derivation_operation_t * operation,
                                           psa_key_handle_t * handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_key_derivation_abort(psa_key_derivation_operation_t * operation)
{
    return PSA_SUCCESS;
}

psa_status_t psa_raw_key_agreement(psa_algorithm_t alg,
                                   psa_key_handle_t private_key,
                                   const uint8_t * peer_key,
                                   size_t peer_key_length,
                                   uint8_t * output,
                                   size_t output_size,
                                   size_t * output_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_generate_random(uint8_t * output,
                                 size_t output_size)
{
    return PSA_SUCCESS;
}

psa_status_t psa_generate_key(const psa_key_attributes_t * attributes,
                              psa_key_handle_t * handle)
{
    return PSA_SUCCESS;
}



