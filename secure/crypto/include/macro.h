#pragma once

#define COUNT(arr)		((sizeof(arr) / sizeof(*arr)))

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

