#include "ed25519.h"

#ifdef BLAKE2_OVER_SHA512
#include <blake2.h>
#else
#include "sha512.h"
#endif

#include "ge.h"


void ed25519_create_keypair(unsigned char *public_key, unsigned char *private_key, const unsigned char *seed) {
    ge_p3 A;
#ifdef BLAKE2_OVER_SHA512
    blake2(private_key, BLAKE2B_OUTBYTES, seed, 32, NULL, 0);
#else
    sha512(seed, 32, private_key);
#endif
    private_key[0] &= 248;
    private_key[31] &= 63;
    private_key[31] |= 64;

    ge_scalarmult_base(&A, private_key);
    ge_p3_tobytes(public_key, &A);
}
