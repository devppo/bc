#include "ed25519.h"

#include <blake2.h>

#include "ge.h"
#include "sc.h"


void ed25519_sign(unsigned char *signature, const unsigned char *message, size_t message_len, const unsigned char *public_key, const unsigned char *private_key) {
    blake2b_state S;
    unsigned char hram[BLAKE2B_OUTBYTES];
    unsigned char r[BLAKE2B_OUTBYTES];
    ge_p3 R;

    blake2b_init(&S, BLAKE2B_OUTBYTES);
    blake2b_update(&S, private_key + 32, 32);
    blake2b_update(&S, message, message_len);
    blake2b_final(&S, r, BLAKE2B_OUTBYTES);

    sc_reduce(r);
    ge_scalarmult_base(&R, r);
    ge_p3_tobytes(signature, &R);

    blake2b_init(&S, BLAKE2B_OUTBYTES);
    blake2b_update(&S, signature, 32);
    blake2b_update(&S, public_key, 32);
    blake2b_update(&S, message, message_len);
    blake2b_final(&S, hram, BLAKE2B_OUTBYTES);

    sc_reduce(hram);
    sc_muladd(signature + 32, hram, private_key, r);
}
