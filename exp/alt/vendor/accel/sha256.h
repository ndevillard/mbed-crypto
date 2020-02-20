#ifndef _VENDOR_ACCEL_SHA256_H
#define _VENDOR_ACCEL_SHA256_H

int vendor_accel_sha256_setup(vendor_accel_sha256_context * ctx);
int vendor_accel_sha256_update(vendor_accel_sha256_context * ctx, uint8_t * input, size_t len);
int vendor_accel_sha256_finish(vendor_accel_sha256_context * ctx, uint8_t * hash, size_t sz, size_t * written);

int vendor_accel_sha256_compute(
    uint8_t * input,
    size_t    len,
    uint8_t * hash,
    size_t    hash_sz,
    size_t  * hash_written);


#endif
