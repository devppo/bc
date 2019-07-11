#ifndef _CRYPTO_H_
#define _CRYPTO_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>
#include <math.h>

#include "macro.h"
#include "defs.h"
#include "export_decl.h"
#include "types.h"

#include "blake2.h"
#include "ed25519.h"

typedef struct hash_type : tarr_type<BLAKE2B_OUTBYTES> {
    hash_type() = default;
    hash_type(const unsigned char *Data, const size_t DataSz) {
        apply(Data, DataSz);
    }
    bool apply(const unsigned char *Data, const size_t DataSz) {
        return blake2(data, get_sz(), Data, DataSz, nullptr, 0) == 0;
    }
} key_type;

extern "C"
{
    EXPORT bool verify(unsigned char *data,
                       size_t data_sz,
                       const unsigned char *public_key,
                       size_t public_key_sz,
                       const unsigned char *signature,
                       size_t signature_sz,
                       char *Status = nullptr,
                       size_t StatusSz = 0);
    EXPORT bool sign(unsigned char *data,
                     size_t data_sz,
                     const unsigned char *public_key,
                     size_t public_key_sz,
                     const unsigned char *private_key,
                     size_t private_key_sz,
                     unsigned char *signature,
                     size_t signature_sz,
                     char *Status = nullptr,
                     size_t StatusSz = 0);
    EXPORT bool gen_keys_pair(unsigned char *public_key_buffer,
                              size_t public_key_sz,
                              unsigned char *private_key_buffer,
                              size_t private_key_sz,
                              char *Status = nullptr,
                              size_t StatusSz = 0);
	EXPORT uint64_t calc_crc_bin_data(unsigned char *data, unsigned int data_sz);
}

#endif
