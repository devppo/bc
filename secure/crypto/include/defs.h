#ifndef _DEFS_H_
#define _DEFS_H_

#ifdef _WIN32
#ifndef WIN32
#define WIN32
#endif
#endif

#ifdef __GNUC__
# ifdef __amd64__
#  ifdef __linux__
    #define GLIBC_COMPAT_SYMBOL(FFF) __asm__(".symver " #FFF "," #FFF "@GLIBC_2.25");
#  else
    #define GLIBC_COMPAT_SYMBOL(FFF)
#  endif
# else
	#error "x86 systems not supported"
# endif
#endif

//Definitions for MacOS X
#ifndef EACCES
#define	EACCES		13	/* Permission denied */
#endif

#ifndef ENOENT
#define	ENOENT		 2	/* No such file or directory */
#endif

#ifndef GLOB_ONLYDIR
#define GLOB_ONLYDIR	 (1 << 13)
#endif

#ifdef _WIN32
#define CLOSESOCKET(s)  closesocket(s)
#else
# ifdef TARGET_OS_MAC
# define CLOSESOCKET(s)  close(s)
# else
# define CLOSESOCKET(s)  close(s)
# endif
#endif
/*
#ifdef _WIN32

#define NET_ERR(_op) {\
    ra_log.err("%s failure: 0x%08X",\
        _op, WSAGetLastError());\
}

#else

#define NET_ERR(_op) {\
    ra_log.err("%s failure: 0x%08X (%s)",\
        _op, errno, strerror(errno));\
}

#endif
*/

#define MINIMAL_STATUS_LENGTH       0x200

#define SIGNATURE_STR               "Signature"
#define PUBLIC_KEY_STR              "Public Key"
#define PRIVATE_KEY_STR             "Private Key"
#define USER_DATA_STR               "User Data"
#define KEYS_PAIR_STR               "Keys Pair"

#define INTERNAL_ERR                "Internal error %d"
#define INVALID_ARG_ERR             "Invalid argument"
#define ACCESS_ERR                  "Access denied"
#define OUT_OF_MEM                  "Out of memory"
#define NOT_IMPLEMENTED             "Not implemented"

#define MINIMIZE

#define BLAKE2_64

#ifdef BLAKE2_64

#define BLAKE2_OVER_SHA512

#define BLAKE2                  blake2b
#define BLAKE2_BLOCKBYTES       BLAKE2B_BLOCKBYTES
#define BLAKE2_OUTBYTES         BLAKE2B_OUTBYTES
#define BLAKE2_KEYBYTES         BLAKE2B_KEYBYTES
#define BLAKE2_SALTBYTES        BLAKE2B_SALTBYTES
#define BLAKE2_PERSONALBYTES    BLAKE2B_PERSONALBYTES
#define blake2_state__          blake2b_state__
#define blake2_param__          blake2b_param__
#define blake2_state            blake2b_state
#define blake2_param            blake2b_param
#define blake2x_state__         blake2xb_state__
#define blake2_init             blake2b_init
#define blake2_init_key         blake2b_init_key
#define blake2_init_param       blake2b_init_param
#define blake2_update           blake2b_update
#define blake2_final            blake2b_final

#else

#define BLAKE2                  blake2s
#define BLAKE2_BLOCKBYTES       BLAKE2S_BLOCKBYTES
#define BLAKE2_OUTBYTES         BLAKE2S_OUTBYTES
#define BLAKE2_KEYBYTES         BLAKE2S_KEYBYTES
#define BLAKE2_SALTBYTES        BLAKE2S_SALTBYTES
#define BLAKE2_PERSONALBYTES    BLAKE2S_PERSONALBYTES
#define blake2_state__          blake2s_state__
#define blake2_param__          blake2s_param__
#define blake2_state            blake2s_state
#define blake2_param            blake2s_param
#define blake2x_state__         blake2xs_state__
#define blake2_init             blake2s_init
#define blake2_init_key         blake2s_init_key
#define blake2_init_param       blake2s_init_param
#define blake2_update           blake2s_update
#define blake2_final            blake2s_final

#endif

#endif
