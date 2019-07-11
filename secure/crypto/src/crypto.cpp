#include "crypto.h"

//using namespace racrypto;
using namespace std::chrono;

extern "C"
{
bool sign(unsigned char *data,
          size_t data_sz,
          const unsigned char *public_key,
          const size_t public_key_sz,
          const unsigned char *private_key,
          const size_t private_key_sz,
          unsigned char *signature,
          const size_t signature_sz,
          char *Status,
          size_t StatusSz) {
    SILENCE

    CHECK_SZ(signature_sz, SIGNATURE_STR, sign_type)
    CHECK_SZ(public_key_sz, PUBLIC_KEY_STR, public_type)
    CHECK_SZ(private_key_sz, PRIVATE_KEY_STR, private_type)
    CHECK_NULL(data, USER_DATA_STR)
    CHECK_NULL(signature, SIGNATURE_STR)
    CHECK_NULL(public_key, PUBLIC_KEY_STR)
    CHECK_NULL(private_key, PRIVATE_KEY_STR)
    try {
        hash_type hash(data, data_sz);
        public_type &pub = *(public_type *)public_key;
        private_type &priv = *(private_type *)private_key;
        sign_type &sign = *(sign_type *)signature;
        auto result = sign.apply(hash.data,
                hash_type::get_sz(),
                pub,
                priv);
        if(result) {
            SPRINTF(Status, "%s generated", SIGNATURE_STR);
        } else {
            SPRINTF(Status, "%s generation failure", SIGNATURE_STR);
        }
        return result;
    } catch (const std::exception &e) {
        SPRINTF(Status, "EXCEPTION %s", e.what());
        return false;
    }
}

bool verify(unsigned char *data,
            size_t data_sz,
            const unsigned char *public_key,
            const size_t public_key_sz,
            const unsigned char *signature,
            const size_t signature_sz,
            char *Status,
            size_t StatusSz) {
    SILENCE

    CHECK_SZ(signature_sz, SIGNATURE_STR, sign_type)
    CHECK_SZ(public_key_sz, PUBLIC_KEY_STR, public_type)
    CHECK_NULL(data, USER_DATA_STR)
    CHECK_NULL(signature, SIGNATURE_STR)
    CHECK_NULL(public_key, PUBLIC_KEY_STR)

    hash_type hash(data, data_sz);
    try {
        sign_type &sign = *(sign_type *)signature;
        public_type &pub = *(public_type *)public_key;
        auto result = sign.check(hash.data, hash_type::get_sz(), pub);
        if (result) {
            SPRINTF(Status, "%s verified", SIGNATURE_STR);
        } else {
            SPRINTF(Status, "%s inconsistency", SIGNATURE_STR);
        }
        return result;
    } catch (const std::exception &e) {
        SPRINTF(Status, "EXCEPTION %s", e.what());
        return false;
    }
}

bool gen_keys_pair(unsigned char *public_key_buffer,
                   size_t public_key_sz,
                   unsigned char *private_key_buffer,
                   size_t private_key_sz,
                   char *Status,
                   size_t StatusSz) {
    SILENCE

    CHECK_TYPE_SZ(public_key_sz, PUBLIC_KEY_STR, public_type)
    CHECK_TYPE_SZ(private_key_sz, PRIVATE_KEY_STR, private_type)
    CHECK_NULL(PUBLIC_KEY_STR, public_key_buffer)
    CHECK_NULL(PRIVATE_KEY_STR, private_key_buffer)

    try {
        Context context;
        ed25519_create_keypair(public_key_buffer, private_key_buffer, context.data);
        return true;
    } catch (const std::exception &e) {
        SPRINTF(Status, "EXCEPTION %s", e.what());
        return false;
    }
}

uint64_t calc_crc_bin_data(unsigned char *data, unsigned int data_sz) {
	uint64_t res = 0;
	for (unsigned int i = 0; i < data_sz; i++) {
		res += data[i] * 0x5FB7D03C81AE5243;
		res ^= (res >> 8);
	}
	return res;
}
}
