
#ifndef _PSA_CRYPTO_H_
#define _PSA_CRYPTO_H_

#include <stddef.h>
#include <stdint.h>

/**
 * Typedef
 */
typedef unsigned psa_key_handle_t;
typedef struct psa_key_attributes_s psa_key_attributes_t;
typedef struct psa_mac_operation_s psa_mac_operation_t;
typedef struct psa_cipher_operation_s psa_cipher_operation_t;
typedef struct psa_aead_operation_s psa_aead_operation_t;
typedef struct psa_key_derivation_s psa_key_derivation_operation_t;

struct psa_key_attributes_s {};
struct psa_mac_operation_s {};
struct psa_cipher_operation_s {};
struct psa_aead_operation_s {};
struct psa_key_derivation_s {};

typedef int32_t psa_status_t;
#define PSA_SUCCESS  ((psa_status_t)0)
#define PSA_ERROR_GENERIC_ERROR  ((psa_status_t)-132)
#define PSA_ERROR_NOT_SUPPORTED  ((psa_status_t)-134)
#define PSA_ERROR_NOT_PERMITTED  ((psa_status_t)-133)
#define PSA_ERROR_BUFFER_TOO_SMALL  ((psa_status_t)-138)
#define PSA_ERROR_ALREADY_EXISTS  ((psa_status_t)-139)
#define PSA_ERROR_DOES_NOT_EXIST  ((psa_status_t)-140)
#define PSA_ERROR_BAD_STATE  ((psa_status_t)-137)
#define PSA_ERROR_INVALID_ARGUMENT  ((psa_status_t)-135)
#define PSA_ERROR_INSUFFICIENT_MEMORY  ((psa_status_t)-141)
#define PSA_ERROR_INSUFFICIENT_STORAGE  ((psa_status_t)-142)
#define PSA_ERROR_COMMUNICATION_FAILURE  ((psa_status_t)-145)
#define PSA_ERROR_STORAGE_FAILURE  ((psa_status_t)-146)
#define PSA_ERROR_HARDWARE_FAILURE  ((psa_status_t)-147)
#define PSA_ERROR_CORRUPTION_DETECTED  ((psa_status_t)-151)
#define PSA_ERROR_INSUFFICIENT_ENTROPY  ((psa_status_t)-148)
#define PSA_ERROR_INVALID_SIGNATURE  ((psa_status_t)-149)
#define PSA_ERROR_INVALID_PADDING  ((psa_status_t)-150)
#define PSA_ERROR_INSUFFICIENT_DATA  ((psa_status_t)-143)
#define PSA_ERROR_INVALID_HANDLE  ((psa_status_t)-136)

typedef uint32_t psa_key_type_t;
typedef uint16_t psa_ecc_curve_t;
typedef uint16_t psa_dh_group_t;

typedef uint32_t psa_algorithm_t;
#define PSA_KEY_TYPE_NONE  ((psa_key_type_t)0x00000000)
#define PSA_KEY_TYPE_VENDOR_FLAG  ((psa_key_type_t)0x80000000)
#define PSA_KEY_TYPE_IS_VENDOR_DEFINED(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_UNSTRUCTURED(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_ASYMMETRIC(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_PUBLIC_KEY(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_KEY_PAIR(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_KEY_PAIR_OF_PUBLIC_KEY(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_PUBLIC_KEY_OF_KEY_PAIR(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_RAW_DATA  ((psa_key_type_t)0x50000001)
#define PSA_KEY_TYPE_HMAC  ((psa_key_type_t)0x51000000)
#define PSA_KEY_TYPE_DERIVE  ((psa_key_type_t)0x52000000)
#define PSA_KEY_TYPE_AES  ((psa_key_type_t)0x40000001)
#define PSA_KEY_TYPE_DES  ((psa_key_type_t)0x40000002)
#define PSA_KEY_TYPE_CAMELLIA  ((psa_key_type_t)0x40000003)
#define PSA_KEY_TYPE_ARC4  ((psa_key_type_t)0x40000004)
#define PSA_KEY_TYPE_CHACHA20  ((psa_key_type_t)0x40000005)
#define PSA_KEY_TYPE_RSA_PUBLIC_KEY  ((psa_key_type_t)0x60010000)
#define PSA_KEY_TYPE_RSA_KEY_PAIR  ((psa_key_type_t)0x70010000)
#define PSA_KEY_TYPE_IS_RSA(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_ECC_KEY_PAIR(curve)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_ECC_PUBLIC_KEY(curve)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_ECC(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_ECC_PUBLIC_KEY(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_GET_CURVE(type)  /* <IMPDEF expression> */
#define PSA_ECC_CURVE_SECT163K1  ((psa_ecc_curve_t) 0x0001)
#define PSA_ECC_CURVE_SECT163R1  ((psa_ecc_curve_t) 0x0002)
#define PSA_ECC_CURVE_SECT163R2  ((psa_ecc_curve_t) 0x0003)
#define PSA_ECC_CURVE_SECT193R1  ((psa_ecc_curve_t) 0x0004)
#define PSA_ECC_CURVE_SECT193R2  ((psa_ecc_curve_t) 0x0005)
#define PSA_ECC_CURVE_SECT233K1  ((psa_ecc_curve_t) 0x0006)
#define PSA_ECC_CURVE_SECT233R1  ((psa_ecc_curve_t) 0x0007)
#define PSA_ECC_CURVE_SECT239K1  ((psa_ecc_curve_t) 0x0008)
#define PSA_ECC_CURVE_SECT283K1  ((psa_ecc_curve_t) 0x0009)
#define PSA_ECC_CURVE_SECT283R1  ((psa_ecc_curve_t) 0x000a)
#define PSA_ECC_CURVE_SECT409K1  ((psa_ecc_curve_t) 0x000b)
#define PSA_ECC_CURVE_SECT409R1  ((psa_ecc_curve_t) 0x000c)
#define PSA_ECC_CURVE_SECT571K1  ((psa_ecc_curve_t) 0x000d)
#define PSA_ECC_CURVE_SECT571R1  ((psa_ecc_curve_t) 0x000e)
#define PSA_ECC_CURVE_SECP160K1  ((psa_ecc_curve_t) 0x000f)
#define PSA_ECC_CURVE_SECP160R1  ((psa_ecc_curve_t) 0x0010)
#define PSA_ECC_CURVE_SECP160R2  ((psa_ecc_curve_t) 0x0011)
#define PSA_ECC_CURVE_SECP192K1  ((psa_ecc_curve_t) 0x0012)
#define PSA_ECC_CURVE_SECP192R1  ((psa_ecc_curve_t) 0x0013)
#define PSA_ECC_CURVE_SECP224K1  ((psa_ecc_curve_t) 0x0014)
#define PSA_ECC_CURVE_SECP224R1  ((psa_ecc_curve_t) 0x0015)
#define PSA_ECC_CURVE_SECP256K1  ((psa_ecc_curve_t) 0x0016)
#define PSA_ECC_CURVE_SECP256R1  ((psa_ecc_curve_t) 0x0017)
#define PSA_ECC_CURVE_SECP384R1  ((psa_ecc_curve_t) 0x0018)
#define PSA_ECC_CURVE_SECP521R1  ((psa_ecc_curve_t) 0x0019)
#define PSA_ECC_CURVE_BRAINPOOL_P256R1  ((psa_ecc_curve_t) 0x001a)
#define PSA_ECC_CURVE_BRAINPOOL_P384R1  ((psa_ecc_curve_t) 0x001b)
#define PSA_ECC_CURVE_BRAINPOOL_P512R1  ((psa_ecc_curve_t) 0x001c)
#define PSA_ECC_CURVE_CURVE25519  ((psa_ecc_curve_t) 0x001d)
#define PSA_ECC_CURVE_CURVE448  ((psa_ecc_curve_t) 0x001e)
#define PSA_KEY_TYPE_DH_KEY_PAIR(group)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_DH_PUBLIC_KEY(group)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_DH(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_DH_KEY_PAIR(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_IS_DH_PUBLIC_KEY(type)  /* <IMPDEF expression> */
#define PSA_KEY_TYPE_GET_GROUP(type)  /* <IMPDEF expression> */
#define PSA_BLOCK_CIPHER_BLOCK_SIZE(type)  /* <IMPDEF expression> */
#define PSA_ALG_IS_MAC(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_CIPHER(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_AEAD(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_SIGN(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_ASYMMETRIC_ENCRYPTION(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_KEY_AGREEMENT(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_KEY_DERIVATION(alg)  /* <IMPDEF expression> */
#define PSA_ALG_HMAC(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_HMAC(alg)  /* <IMPDEF expression> */
#define PSA_ALG_TRUNCATED_MAC(mac_alg, mac_length)  /* <IMPDEF expression> */
#define PSA_ALG_FULL_LENGTH_MAC(mac_alg)  /* <IMPDEF expression> */
#define PSA_MAC_TRUNCATED_LENGTH(mac_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_BLOCK_CIPHER_MAC(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_STREAM_CIPHER(alg)  /* <IMPDEF expression> */
#define PSA_ALG_ARC4  ((psa_algorithm_t)0x04800001)
#define PSA_ALG_CHACHA20  ((psa_algorithm_t)0x04800005)
#define PSA_ALG_CTR  ((psa_algorithm_t)0x04c00001)
#define PSA_ALG_XTS  ((psa_algorithm_t)0x044000ff)
#define PSA_ALG_CBC_NO_PADDING  ((psa_algorithm_t)0x04600100)
#define PSA_ALG_CBC_PKCS7  ((psa_algorithm_t)0x04600101)
#define PSA_ALG_IS_AEAD_ON_BLOCK_CIPHER(alg)  /* <IMPDEF expression> */
#define PSA_ALG_CCM  ((psa_algorithm_t)0x06401001)
#define PSA_ALG_GCM  ((psa_algorithm_t)0x06401002)
#define PSA_ALG_CHACHA20_POLY1305  ((psa_algorithm_t)0x06001005)
#define PSA_ALG_AEAD_WITH_TAG_LENGTH(aead_alg, tag_length) \
    /* <IMPDEF expression> */
#define PSA_ALG_AEAD_WITH_DEFAULT_TAG_LENGTH(aead_alg) \
    /* <IMPDEF expression> */
#define PSA_ALG_RSA_PKCS1V15_SIGN(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_RSA_PKCS1V15_SIGN_RAW  PSA_ALG_RSA_PKCS1V15_SIGN_BASE
#define PSA_ALG_RSA_PSS(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_ECDSA(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_ECDSA_ANY  PSA_ALG_ECDSA_BASE
#define PSA_ALG_DETERMINISTIC_ECDSA(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_HASH_AND_SIGN(alg)  /* <IMPDEF expression> */
#define PSA_ALG_SIGN_GET_HASH(alg)  /* <IMPDEF expression> */
#define PSA_ALG_RSA_PKCS1V15_CRYPT  ((psa_algorithm_t)0x12020000)
#define PSA_ALG_RSA_OAEP(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_HKDF(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_HKDF(alg)  /* <IMPDEF expression> */
#define PSA_ALG_TLS12_PRF(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_TLS12_PRF(alg)  /* <IMPDEF expression> */
#define PSA_ALG_TLS12_PSK_TO_MS(hash_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_TLS12_PSK_TO_MS(alg)  /* <IMPDEF expression> */
#define PSA_ALG_KEY_AGREEMENT(ka_alg, kdf_alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_RAW_KEY_AGREEMENT(alg)  /* <IMPDEF expression> */
#define PSA_ALG_FFDH  ((psa_algorithm_t)0x30100000)
#define PSA_ALG_IS_FFDH(alg)  /* <IMPDEF expression> */
#define PSA_ALG_ECDH  ((psa_algorithm_t)0x30200000)
#define PSA_ALG_IS_ECDH(alg)  /* <IMPDEF expression> */
#define PSA_ALG_IS_WILDCARD(alg)  /* <IMPDEF expression> */
typedef uint32_t psa_key_lifetime_t;
typedef uint32_t psa_key_id_t;
#define PSA_KEY_LIFETIME_VOLATILE  ((psa_key_lifetime_t)0x00000000)
#define PSA_KEY_LIFETIME_PERSISTENT  ((psa_key_lifetime_t)0x00000001)
#define PSA_KEY_ID_USER_MIN  ((psa_key_id_t)0x00000001)
#define PSA_KEY_ID_USER_MAX  ((psa_key_id_t)0x3fffffff)
#define PSA_KEY_ID_VENDOR_MIN  ((psa_key_id_t)0x40000000)
#define PSA_KEY_ID_VENDOR_MAX  ((psa_key_id_t)0x7fffffff)
typedef uint32_t psa_key_usage_t;
#define PSA_KEY_USAGE_EXPORT  ((psa_key_usage_t)0x00000001)
#define PSA_KEY_USAGE_COPY  ((psa_key_usage_t)0x00000002)
#define PSA_KEY_USAGE_ENCRYPT  ((psa_key_usage_t)0x00000100)
#define PSA_KEY_USAGE_DECRYPT  ((psa_key_usage_t)0x00000200)
#define PSA_KEY_USAGE_SIGN  ((psa_key_usage_t)0x00000400)
#define PSA_KEY_USAGE_VERIFY  ((psa_key_usage_t)0x00000800)
#define PSA_KEY_USAGE_DERIVE  ((psa_key_usage_t)0x00001000)
typedef uint16_t psa_key_derivation_step_t;
#define PSA_KEY_DERIVATION_INPUT_SECRET  ((psa_key_derivation_step_t)0x0101)
#define PSA_KEY_DERIVATION_INPUT_LABEL  ((psa_key_derivation_step_t)0x0201)
#define PSA_KEY_DERIVATION_INPUT_SALT  ((psa_key_derivation_step_t)0x0202)
#define PSA_KEY_DERIVATION_INPUT_INFO  ((psa_key_derivation_step_t)0x0203)
#define PSA_KEY_DERIVATION_INPUT_SEED  ((psa_key_derivation_step_t)0x0204)
#define PSA_MAC_MAX_SIZE  PSA_HASH_MAX_SIZE
#define PSA_AEAD_TAG_LENGTH(alg)  /* <IMPDEF expression> */
#define PSA_ECC_CURVE_BITS(curve)  /*...*/
#define PSA_ALG_TLS12_PSK_TO_MS_MAX_PSK_LEN  128
#define PSA_ASYMMETRIC_SIGNATURE_MAX_SIZE  /* <IMPDEF constant> */
#define PSA_MAX_BLOCK_CIPHER_BLOCK_SIZE  /* <IMPDEF constant> */
#define PSA_MAC_FINAL_SIZE(key_type, key_bits, alg)  /* <IMPDEF expression> */
#define PSA_AEAD_ENCRYPT_OUTPUT_SIZE(alg, plaintext_length) \
    /* <IMPDEF expression> */
#define PSA_AEAD_DECRYPT_OUTPUT_SIZE(alg, ciphertext_length) \
    /* <IMPDEF expression> */
#define PSA_AEAD_UPDATE_OUTPUT_SIZE(alg, input_length) \
    /* <IMPDEF expression> */
#define PSA_AEAD_FINISH_OUTPUT_SIZE(alg)  /* <IMPDEF expression> */
#define PSA_AEAD_VERIFY_OUTPUT_SIZE(alg)  /* <IMPDEF expression> */
#define PSA_ECDSA_SIGNATURE_SIZE(curve_bits)  /* <IMPDEF expression> */
#define PSA_ASYMMETRIC_SIGN_OUTPUT_SIZE(key_type, key_bits, alg) \
    /* <IMPDEF expression> */
#define PSA_ASYMMETRIC_ENCRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
    /* <IMPDEF expression> */
#define PSA_ASYMMETRIC_DECRYPT_OUTPUT_SIZE(key_type, key_bits, alg) \
    /* <IMPDEF expression> */
#define PSA_KEY_EXPORT_MAX_SIZE(key_type, key_bits)  /* <IMPDEF expression> */


/**
 * Functions
 */

psa_status_t psa_crypto_init(void);
#define PSA_KEY_ATTRIBUTES_INIT  /* <IMPDEF constant> */
psa_key_attributes_t psa_key_attributes_init(void);

/** Key management */
void psa_set_key_id(
    psa_key_attributes_t * attributes,
    psa_key_id_t id);

void psa_set_key_lifetime(
    psa_key_attributes_t * attributes,
    psa_key_lifetime_t lifetime);

psa_key_id_t psa_get_key_id(
    const psa_key_attributes_t * attributes);

psa_key_lifetime_t psa_get_key_lifetime(
    const psa_key_attributes_t * attributes);

void psa_set_key_usage_flags(
    psa_key_attributes_t * attributes,
    psa_key_usage_t usage_flags);

psa_key_usage_t psa_get_key_usage_flags(
    const psa_key_attributes_t * attributes);

void psa_set_key_algorithm(
    psa_key_attributes_t * attributes,
    psa_algorithm_t alg);

psa_algorithm_t psa_get_key_algorithm(
    const psa_key_attributes_t * attributes);

void psa_set_key_type(
    psa_key_attributes_t * attributes,
    psa_key_type_t type);

void psa_set_key_bits(
    psa_key_attributes_t * attributes,
    size_t bits);

psa_key_type_t psa_get_key_type(
    const psa_key_attributes_t * attributes);

size_t psa_get_key_bits(
    const psa_key_attributes_t * attributes);

psa_status_t psa_get_key_attributes(
    psa_key_handle_t handle,
    psa_key_attributes_t * attributes);

void psa_reset_key_attributes(
    psa_key_attributes_t * attributes);

psa_status_t psa_open_key(
    psa_key_id_t id,
    psa_key_handle_t * handle);

psa_status_t psa_close_key(psa_key_handle_t handle);

psa_status_t psa_import_key(
    const psa_key_attributes_t * attributes,
    const uint8_t * data,
    size_t data_length,
    psa_key_handle_t * handle);

psa_status_t psa_destroy_key(psa_key_handle_t handle);

psa_status_t psa_export_key(
    psa_key_handle_t handle,
    uint8_t * data,
    size_t data_size,
    size_t * data_length);

psa_status_t psa_export_public_key(
    psa_key_handle_t handle,
    uint8_t * data,
    size_t data_size,
    size_t * data_length);

psa_status_t psa_copy_key(
    psa_key_handle_t source_handle,
    const psa_key_attributes_t * attributes,
    psa_key_handle_t * target_handle);

/** MAC */
#define PSA_MAC_OPERATION_INIT  /* <IMPDEF constant> */
psa_status_t psa_mac_compute(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    uint8_t * mac,
    size_t mac_size,
    size_t * mac_length);

psa_status_t psa_mac_verify(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    const uint8_t * mac,
    const size_t mac_length);

psa_mac_operation_t psa_mac_operation_init(void);

psa_status_t psa_mac_sign_setup(
    psa_mac_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_mac_verify_setup(
    psa_mac_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_mac_update(
    psa_mac_operation_t * operation,
    const uint8_t * input,
    size_t input_length);

psa_status_t psa_mac_sign_finish(
    psa_mac_operation_t * operation,
    uint8_t * mac,
    size_t mac_size,
    size_t * mac_length);

psa_status_t psa_mac_verify_finish(
    psa_mac_operation_t * operation,
    const uint8_t * mac,
    size_t mac_length);

psa_status_t psa_mac_abort(psa_mac_operation_t * operation);
#define PSA_CIPHER_OPERATION_INIT  /* <IMPDEF constant> */

/** Cipher */
psa_status_t psa_cipher_encrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_cipher_decrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);

psa_cipher_operation_t psa_cipher_operation_init(void);

psa_status_t psa_cipher_encrypt_setup(
    psa_cipher_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_cipher_decrypt_setup(
    psa_cipher_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_cipher_generate_iv(
    psa_cipher_operation_t * operation,
    unsigned char * iv,
    size_t iv_size,
    size_t * iv_length);

psa_status_t psa_cipher_set_iv(
    psa_cipher_operation_t * operation,
    const unsigned char * iv,
    size_t iv_length);

psa_status_t psa_cipher_update(
    psa_cipher_operation_t * operation,
    const uint8_t * input,
    size_t input_length,
    unsigned char * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_cipher_finish(
    psa_cipher_operation_t * operation,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_cipher_abort(psa_cipher_operation_t * operation);



/** AEAD */
#define PSA_AEAD_OPERATION_INIT  /* <IMPDEF constant> */
psa_status_t psa_aead_encrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * nonce,
    size_t nonce_length,
    const uint8_t * additional_data,
    size_t additional_data_length,
    const uint8_t * plaintext,
    size_t plaintext_length,
    uint8_t * ciphertext,
    size_t ciphertext_size,
    size_t * ciphertext_length);

psa_status_t psa_aead_decrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * nonce,
    size_t nonce_length,
    const uint8_t * additional_data,
    size_t additional_data_length,
    const uint8_t * ciphertext,
    size_t ciphertext_length,
    uint8_t * plaintext,
    size_t plaintext_size,
    size_t * plaintext_length);

psa_aead_operation_t psa_aead_operation_init(void);

psa_status_t psa_aead_encrypt_setup(
    psa_aead_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_aead_decrypt_setup(
    psa_aead_operation_t * operation,
    psa_key_handle_t handle,
    psa_algorithm_t alg);

psa_status_t psa_aead_generate_nonce(
    psa_aead_operation_t * operation,
    unsigned char * nonce,
    size_t nonce_size,
    size_t * nonce_length);

psa_status_t psa_aead_set_nonce(
    psa_aead_operation_t * operation,
    const unsigned char * nonce,
    size_t nonce_length);

psa_status_t psa_aead_set_lengths(
    psa_aead_operation_t * operation,
    size_t ad_length,
    size_t plaintext_length);

psa_status_t psa_aead_update_ad(
    psa_aead_operation_t * operation,
    const uint8_t * input,
    size_t input_length);

psa_status_t psa_aead_update(
    psa_aead_operation_t * operation,
    const uint8_t * input,
    size_t input_length,
    unsigned char * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_aead_finish(
    psa_aead_operation_t * operation,
    uint8_t * ciphertext,
    size_t ciphertext_size,
    size_t * ciphertext_length,
    uint8_t * tag,
    size_t tag_size,
    size_t * tag_length);

psa_status_t psa_aead_verify(
    psa_aead_operation_t * operation,
    uint8_t * plaintext,
    size_t plaintext_size,
    size_t * plaintext_length,
    const uint8_t * tag,
    size_t tag_length);

psa_status_t psa_aead_abort(psa_aead_operation_t * operation);

/** Asymmetric */
psa_status_t psa_asymmetric_sign(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * hash,
    size_t hash_length,
    uint8_t * signature,
    size_t signature_size,
    size_t * signature_length);

psa_status_t psa_asymmetric_verify(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * hash,
    size_t hash_length,
    const uint8_t * signature,
    size_t signature_length);

psa_status_t psa_asymmetric_encrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    const uint8_t * salt,
    size_t salt_length,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_asymmetric_decrypt(
    psa_key_handle_t handle,
    psa_algorithm_t alg,
    const uint8_t * input,
    size_t input_length,
    const uint8_t * salt,
    size_t salt_length,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);



/** Key derivation */

#define PSA_KEY_DERIVATION_OPERATION_INIT  /* <IMPDEF constant> */
#define PSA_KEY_DERIVATION_UNLIMITED_CAPACITY  /* <IMPDEF constant> */

psa_key_derivation_operation_t psa_key_derivation_operation_init(void);

psa_status_t psa_key_derivation_setup(
    psa_key_derivation_operation_t * operation,
    psa_algorithm_t alg);

psa_status_t psa_key_derivation_get_capacity(
    const psa_key_derivation_operation_t * operation,
    size_t * capacity);

psa_status_t psa_key_derivation_set_capacity(
    psa_key_derivation_operation_t * operation,
    size_t capacity);

psa_status_t psa_key_derivation_input_bytes(
    psa_key_derivation_operation_t * operation,
    psa_key_derivation_step_t step,
    const uint8_t * data,
    size_t data_length);

psa_status_t psa_key_derivation_input_key(
    psa_key_derivation_operation_t * operation,
    psa_key_derivation_step_t step,
    psa_key_handle_t handle);

psa_status_t psa_key_derivation_key_agreement(
    psa_key_derivation_operation_t * operation,
    psa_key_derivation_step_t step,
    psa_key_handle_t private_key,
    const uint8_t * peer_key,
    size_t peer_key_length);

psa_status_t psa_key_derivation_output_bytes(
    psa_key_derivation_operation_t * operation,
    uint8_t * output,
    size_t output_length);

psa_status_t psa_key_derivation_output_key(
    const psa_key_attributes_t * attributes,
    psa_key_derivation_operation_t * operation,
    psa_key_handle_t * handle);

psa_status_t psa_key_derivation_abort(
    psa_key_derivation_operation_t * operation);

psa_status_t psa_raw_key_agreement(
    psa_algorithm_t alg,
    psa_key_handle_t private_key,
    const uint8_t * peer_key,
    size_t peer_key_length,
    uint8_t * output,
    size_t output_size,
    size_t * output_length);

psa_status_t psa_generate_random(
    uint8_t * output,
    size_t output_size);

psa_status_t psa_generate_key(
    const psa_key_attributes_t * attributes,
    psa_key_handle_t * handle);

#include "crypto/hash.h"

#endif
