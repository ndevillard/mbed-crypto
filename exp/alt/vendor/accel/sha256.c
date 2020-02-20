#include "sha256.h"
#include <string.h>

int 
vendor_accel_sha256_setup(vendor_accel_sha256_context * ctx)
{
	return 0;
}

int 
vendor_accel_sha256_update(
    vendor_accel_sha256_context * ctx,
	const unsigned char *input,
	size_t ilen)
{
	return 0;
}

int 
vendor_accel_sha256_finish(
    vendor_accel_sha256_context * ctx,
	unsigned char output[32])
{
	return 0;
}

int 
vendor_accel_sha256_compute(
    const unsigned char *input,
	size_t ilen,
	unsigned char output[32],
	int is224)
{
	return 0;
}
