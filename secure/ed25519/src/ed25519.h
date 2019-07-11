#ifndef ED25519_H
#define ED25519_H

#include <stddef.h>
#include <stdlib.h>
#include <exception>
#include <stdexcept>

#include "defs.h"
#include "export_decl.h"
#include "types.h"

#if defined(_WIN32)
    #if defined(ED25519_BUILD_DLL)
        #define ED25519_DECLSPEC EXPORT
    #elif defined(ED25519_DLL)
        #define ED25519_DECLSPEC IMPORT
    #else
        #define ED25519_DECLSPEC
    #endif
#else
    #define ED25519_DECLSPEC
#endif

#define SIGN_SZ         0x40
#define PUBLIC_SZ       0x20
#define PRIVATE_SZ      0x40
#define SEED_SZ         0x20

//typedef tarr_type<SIGN_SZ> sign_type;
typedef tarr_type<PUBLIC_SZ> public_type;
typedef tarr_type<PRIVATE_SZ> private_type;

#ifdef __cplusplus
extern "C" {
#endif

#ifndef ED25519_NO_SEED
int ED25519_DECLSPEC ed25519_create_seed(unsigned char *seed, size_t seed_sz);
#endif

void ED25519_DECLSPEC ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed);
void ED25519_DECLSPEC ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key);
int ED25519_DECLSPEC ed25519_verify(const unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key);

#ifndef MINIMIZE
void ED25519_DECLSPEC ed25519_add_scalar(unsigned char *public_key, unsigned char *private_key, const unsigned char *scalar);
void ED25519_DECLSPEC ed25519_key_exchange(unsigned char *shared_secret, const unsigned char *public_key, const unsigned char *private_key);
#endif

#ifdef __cplusplus
}
#endif

typedef struct seed_type : tarr_type<SEED_SZ> {
    seed_type() {
        ed25519_create_seed(this->data, get_sz());
    }
} SeedType, Context;

typedef struct sign_type : tarr_type<SIGN_SZ> {
    sign_type() = default;
    sign_type(const unsigned char *Data, const size_t DataSz, const public_type &pub, const private_type &priv) {
        apply(Data, DataSz, pub, priv);
    }
    bool apply(const unsigned char *Data, const size_t DataSz, const public_type &pub, const private_type &priv) {
        ed25519_sign(data, Data, DataSz, pub.data, priv.data);
        return true;
    }
    bool check(const unsigned char *Data, const size_t DataSz, const public_type &pub) {
        return (bool)ed25519_verify(data, Data, DataSz, pub.data);
    }
} SignType;

typedef struct ed25519KeyPair {
    public_type public_key;
    private_type private_key;
    ed25519KeyPair() {
        seed_type seed;
        ed25519_create_keypair(public_key.data, private_key.data, seed.data);
        //if(!valid()) throw std::runtime_error("ed25519 Keys Pair is invalid");
    }
    ed25519KeyPair(public_type pub,
        private_type priv) : public_key(pub), private_key(priv)
    {
        if(!valid()) throw std::runtime_error("ed25519 Keys Pair is invalid");
    }
    bool valid() {
        seed_type seed;
        sign_type sign(seed.data, seed_type::get_sz(), public_key, private_key);
        return sign.check(seed.data, seed_type::get_sz(), public_key);
    }
} *Ped25519KeyPair, *Hed25519KeyPair;

#endif
