#ifndef _ALT_VENDORS_H
#define _ALT_VENDORS_H

#include "autoconf.h"

#if CONFIG_ARM_MBEDTLS
#include "arm/mbedtls/vendor.h"
#endif

#if CONFIG_INTEL_TINYCRYPT
#include "intel/tinycrypt/vendor.h"
#endif

#endif