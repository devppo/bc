#ifndef _MACRO_H_
#define _MACRO_H_

#ifdef _WIN32
#define HOMEDIR	(getenv("HOMEPATH"))
#else
#define HOMEDIR	(getenv("HOME"))
#endif

#define PRED(x)			((x) - 1)
#define SUCC(x)			((x) + 1)
#define COUNT(arr)		((sizeof(arr) / sizeof(*arr)))
#define ZEROIZE(p)      (memset((p), 0, sizeof(*(p))))
#define ZEROARR(arr)      (memset((arr), 0, sizeof(arr)))
#define FIELD_OFFS(t, f)    ((size_t)&((t *)nullptr)->f)

#define SPRINTF         if(!b_silent)sprintf
#define SILENCE         bool b_silent = (!Status) || (StatusSz < MINIMAL_STATUS_LENGTH);

#define CHECK_SZ(sz, strObj, t)     if(sz != t::get_sz()) { \
    SPRINTF(Status, \
        "%s size %zu bytes, %zu bytes required", \
        strObj, \
        sz, \
        t::get_sz()); \
     return false; \
}

#define CHECK_TYPE_SZ(sz, strObj, t)     if(sz != sizeof(t)) { \
    SPRINTF(Status, \
        "%s size %zu bytes, %zu bytes required", \
        strObj, \
        sz, \
        sizeof(t)); \
     return false; \
}

#define CHECK_SZ_LESS(sz, min_sz, inst)     if(sz < min_sz) { \
    SPRINTF(Status, \
        "%s size less than %zu", \
        inst, \
        min_sz); \
     return false; \
}

#define CHECK_NULL(strObj, data)    if(!data) { \
    SPRINTF(Status, \
        "%s is empty", \
        strObj); \
    return false; \
}

#define EASYHOST(sin)	inet_ntoa(sin.sin_addr) //sockaddr_in sin
#define EASYPORT(sin)	htons(sin.sin_port)

#define LUA_NEW(t)      ((t *)lua_newuserdata(state, sizeof(t)))

#endif
