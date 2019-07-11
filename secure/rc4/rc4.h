#ifndef RA_CRYPT_RC4_H
#define RA_CRYPT_RC4_H

#include <stdlib.h>
#include "macro.h"
#include "defs.h"
#include "export_decl.h"

#ifdef __cplusplus
extern "C" {
#endif
    EXPORT void rc4crypt(unsigned char *buffer_ptr,
                  unsigned int buffer_len,
                  const unsigned char *key_data_ptr,
                  unsigned int key_data_len);
#ifdef __cplusplus
}
#endif

#endif //RA_CRYPT_RC4_H
