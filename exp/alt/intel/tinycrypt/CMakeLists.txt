target_include_directories(psa_crypto PRIVATE tinycrypt/lib/include)
psa_crypto_sources_ifdef(CONFIG_INTEL_TINYCRYPT tinycrypt/lib/source/utils.c)
psa_crypto_sources_ifdef(CONFIG_INTEL_TINYCRYPT_SHA2_256 tinycrypt/lib/source/sha256.c)

