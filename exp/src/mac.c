#include "psa/crypto.h"


psa_status_t psa_mac_compute(psa_key_handle_t handle,
                             psa_algorithm_t alg,
                             const uint8_t * input,
                             size_t input_length,
                             uint8_t * mac,
                             size_t mac_size,
                             size_t * mac_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_verify(psa_key_handle_t handle,
                            psa_algorithm_t alg,
                            const uint8_t * input,
                            size_t input_length,
                            const uint8_t * mac,
                            const size_t mac_length)
{
    return PSA_SUCCESS;
}

psa_mac_operation_t psa_mac_operation_init(void)
{
}

psa_status_t psa_mac_sign_setup(psa_mac_operation_t * operation,
                                psa_key_handle_t handle,
                                psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_verify_setup(psa_mac_operation_t * operation,
                                  psa_key_handle_t handle,
                                  psa_algorithm_t alg)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_update(psa_mac_operation_t * operation,
                            const uint8_t * input,
                            size_t input_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_sign_finish(psa_mac_operation_t * operation,
                                 uint8_t * mac,
                                 size_t mac_size,
                                 size_t * mac_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_verify_finish(psa_mac_operation_t * operation,
                                   const uint8_t * mac,
                                   size_t mac_length)
{
    return PSA_SUCCESS;
}

psa_status_t psa_mac_abort(psa_mac_operation_t * operation)
{
    return PSA_SUCCESS;
}

