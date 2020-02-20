#ifndef _ALT_ARM_MBEDTLS_SHA256_H
#define _ALT_ARM_MBEDTLS_SHA256_H

#include <stddef.h>
#include <stdint.h>

/**
 * \brief          The SHA-256 context structure.
 *
 *                 The structure is used both for SHA-256 and for SHA-224
 *                 checksum calculations. The choice between these two is
 *                 made in the call to mbedtls_sha256_starts_ret().
 */
typedef struct arm_mbedtls_sha256_context {
	uint32_t	total  [2];	/* !< The number of Bytes processed.  */
	uint32_t	state  [8];	/* !< The intermediate digest state.  */
	unsigned char	buffer[64];	/* !< The data block being processed. */
	int		is224;	/* !< Determines which function to use: 0:
				 * Use SHA-256, or 1: Use SHA-224. */
} arm_mbedtls_sha256_context;

/**
 * \brief          This function starts a SHA-224 or SHA-256 checksum
 *                 calculation.
 * \param ctx      The context to use. This must be initialized.
 * \param is224    This determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int	arm_mbedtls_sha256_setup(arm_mbedtls_sha256_context * ctx, int is224);

/**
 * \brief          This function feeds an input buffer into an ongoing
 *                 SHA-256 checksum calculation.
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int 
arm_mbedtls_sha256_update(
    arm_mbedtls_sha256_context * ctx,
	const unsigned char *input,
	size_t ilen);

/**
 * \brief          This function finishes the SHA-256 operation, and writes
 *                 the result to the output buffer.
 * \param ctx      The SHA-256 context. This must be initialized
 *                 and have a hash operation started.
 * \param output   The SHA-224 or SHA-256 checksum result.
 *                 This must be a writable buffer of length \c 32 Bytes.
 * \return         \c 0 on success.
 * \return         A negative error code on failure.
 */
int 
arm_mbedtls_sha256_finish(
    arm_mbedtls_sha256_context * ctx,
	unsigned char output[32]);

/**
 * \brief          This function calculates the SHA-224 or SHA-256
 *                 checksum of a buffer.
 *                 The function allocates the context, performs the
 *                 calculation, and frees the context.
 *                 The SHA-256 result is calculated as
 *                 output = SHA-256(input buffer).
 *
 * \param input    The buffer holding the data. This must be a readable
 *                 buffer of length \p ilen Bytes.
 * \param ilen     The length of the input data in Bytes.
 * \param output   The SHA-224 or SHA-256 checksum result. This must
 *                 be a writable buffer of length \c 32 Bytes.
 * \param is224    Determines which function to use. This must be
 *                 either \c 0 for SHA-256, or \c 1 for SHA-224.
 */
int	arm_mbedtls_sha256_compute(
    const unsigned char *input,
    size_t	ilen  ,
    unsigned char output[32],
    int	is224);

#endif
