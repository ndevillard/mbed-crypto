#include "psa/crypto.h"


psa_key_attributes_t psa_key_attributes_init(void)
{
    psa_key_attributes_t r;
    return r;
}

void psa_set_key_id(psa_key_attributes_t * attributes,
                    psa_key_id_t id)
{
    return ;
}

void psa_set_key_lifetime(psa_key_attributes_t * attributes,
                          psa_key_lifetime_t lifetime)
{
    return ;
}

psa_key_id_t psa_get_key_id(const psa_key_attributes_t * attributes)
{
    psa_key_id_t r;
    return r;
}

psa_key_lifetime_t psa_get_key_lifetime(const psa_key_attributes_t * attributes)
{
    psa_key_lifetime_t r;
    return r;
}

void psa_set_key_usage_flags(psa_key_attributes_t * attributes,
                             psa_key_usage_t usage_flags)
{
    return ;
}

psa_key_usage_t psa_get_key_usage_flags(const psa_key_attributes_t * attributes)
{
    psa_key_usage_t r;
    return r;
}

void psa_set_key_algorithm(psa_key_attributes_t * attributes,
                           psa_algorithm_t alg)
{
    return ;
}

psa_algorithm_t psa_get_key_algorithm(const psa_key_attributes_t * attributes)
{
    psa_algorithm_t r;
    return r;
}

void psa_set_key_type(psa_key_attributes_t * attributes,
                      psa_key_type_t type)
{
    return ;
}

void psa_set_key_bits(psa_key_attributes_t * attributes,
                      size_t bits)
{
    return ;
}

psa_key_type_t psa_get_key_type(const psa_key_attributes_t * attributes)
{
    psa_key_type_t r;
    return r;
}

size_t psa_get_key_bits(const psa_key_attributes_t * attributes)
{
    return -1;
}

psa_status_t psa_get_key_attributes(psa_key_handle_t handle,
                                    psa_key_attributes_t * attributes)
{
    return PSA_SUCCESS;
}

void psa_reset_key_attributes(psa_key_attributes_t * attributes)
{
    return ;
}


psa_status_t psa_open_key(psa_key_id_t id,
                          psa_key_handle_t * handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_close_key(psa_key_handle_t handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_import_key(const psa_key_attributes_t * attributes,
                            const uint8_t * data,
                            size_t data_length,
                            psa_key_handle_t * handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_destroy_key(psa_key_handle_t handle)
{
    return PSA_SUCCESS;
}

psa_status_t psa_export_key(psa_key_handle_t handle,
                            uint8_t * data,
                            size_t data_size,
                            size_t * data_length)
{
    return PSA_SUCCESS;
}


psa_status_t psa_export_public_key(psa_key_handle_t handle,
                                   uint8_t * data,
                                   size_t data_size,
                                   size_t * data_length)
{
    return PSA_SUCCESS;
}


psa_status_t psa_copy_key(psa_key_handle_t source_handle,
                          const psa_key_attributes_t * attributes,
                          psa_key_handle_t * target_handle)
{
    return PSA_SUCCESS;
}

