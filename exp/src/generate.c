#include "psa/crypto.h"


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



