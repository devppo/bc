#ifndef RA_CRYPT_CURVE25519_H
#define RA_CRYPT_CURVE25519_H

#define CURVE25519_PUBLIC_SZ       0x20
#define CURVE25519_PRIVATE_SZ      0x20
#define CURVE25519_SHARED_SZ       0x20

#include <stdlib.h>
#include <exception>

#include "ed25519.h"
#include "types.h"
#include "crypto.h" //TODO: use another header

typedef tarr_type<CURVE25519_PUBLIC_SZ>curve_public_type;
typedef tarr_type<CURVE25519_PRIVATE_SZ>curve_private_type;
typedef tarr_type<CURVE25519_SHARED_SZ>curve_shared_type;

#ifdef __cplusplus
extern "C" {
#endif

    EXPORT bool curve25519_gen_keys_pair(curve_public_type &pubkey, curve_private_type &privkey);
    EXPORT bool curve25519_get_shared_hash(hash_type &shared_hash, const curve_public_type &their_pubkey,
                                const curve_private_type &our_privkey);

#ifdef __cplusplus
}
#endif

typedef struct curve25519KeyPair {
    curve_public_type public_key;
    curve_private_type private_key;
    curve25519KeyPair() {
        curve25519_gen_keys_pair(public_key, private_key);
        //if(!valid()) throw std::runtime_error("curve25519 keys pair is invalid");
    }
    curve25519KeyPair(curve_public_type &pub,
            curve_private_type &priv) : public_key(pub),
            private_key(priv)
    {
        if(!valid()) throw std::runtime_error("curve25519 keys pair is invalid");
    }
    bool valid() {
        hash_type shared_hash0;
        hash_type shared_hash1;

        curve_public_type pubkey;
        curve_private_type privkey;

        curve25519_gen_keys_pair(pubkey, privkey);
        curve25519_get_shared_hash(shared_hash0, public_key, privkey);
        curve25519_get_shared_hash(shared_hash1, pubkey, private_key);
        return shared_hash0 == shared_hash1;
    }
} *Pcurve25519KeyPair, *Hcurve25519KeyPair;
#endif //RA_CRYPT_CURVE25519_H
