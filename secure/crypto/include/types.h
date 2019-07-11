#pragma once

#include <stdlib.h>
#include <string.h>
#include <string>
#include <stdlib.h>
#include "macro.h"

#ifdef _WIN32
// For unknown reasons this type defined in MSVC with another way;
// to prevent conflicting declaration ifdef made.
#ifndef socklen_t
typedef int socklen_t;
#endif
#endif

template<size_t BYTES> struct tarr_type {
    tarr_type() {
       memset((data), 0, sizeof(data));
    }
    unsigned char data[BYTES];
    static size_t get_bits() {return BYTES << 3;}
    static size_t get_sz() {return BYTES;}
    void print() const {
        char Buffer[0x100] = {'\0'};
        for(size_t i = 0; i < BYTES; ++i)
            sprintf(Buffer + (i << 1), "%02X", data[i]);
        // print buffer on screen
    }
    void randomize() {
        srand((unsigned int)time(nullptr));
        for(size_t i = 0; i < BYTES; ++i)
            data[i] = (unsigned char)(rand() & 0xFF);
    }
    bool to_hex(char *hexBuffer, const size_t hexBufferSz, size_t keyPartLen = 0) const {
        if(hexBufferSz < ((BYTES << 1) + 1)) return false; // Check if size for hex is correct
        if(keyPartLen > BYTES) return false; // For partialy representation
        if(!keyPartLen) keyPartLen = BYTES;
        for (size_t i = 0; i < keyPartLen; ++i)
            sprintf(hexBuffer + (i << 1), "%02X", data[i]);
        return true;
    }
    bool from_hex(const char *hexBuffer) {
        if(hexBuffer == nullptr) return false;
        if(strlen(hexBuffer) != (BYTES << 1)) return false;
        for(size_t i = 0; i < BYTES; ++i) {
            const size_t j = i << 1;
            char ch = hexBuffer[j] - '0';
            if (ch >= 49 && ch <= 55) ch -= 39;	// 'a' - '0'
            else if (ch >= 17 && ch <= 22) ch -= 7;	// 'A' - '0'
            else if (ch < 0 || ch > 16) return false;
            data[i] = (unsigned char)(ch << 4);
            ch = hexBuffer[j + 1] - '0';
            if (ch >= 49 && ch <= 55) ch -= 39;	// 'a' - '0'
            else if (ch >= 17 && ch <= 22) ch -= 7;	// 'A' - '0'
            else if (ch < 0 || ch > 16) return false;
            data[i] += (unsigned char)ch;
        }
        return true;
    }
    void from(const tarr_type &tarr) {
        memcpy(data, tarr.data, BYTES);
    }
    tarr_type<BYTES> &operator=(const tarr_type<BYTES> &tarr) {
        if(&tarr != this)
            memcpy(this->data, tarr.data, BYTES);
        return *this;
    }
    bool empty() {
        tarr_type<BYTES> Empty;
        return *this == Empty;
    }
};

template<size_t BYTES> bool operator<(const tarr_type<BYTES> &tarr0, const tarr_type<BYTES> &tarr1) {
    for(size_t i = 0; i < tarr_type<BYTES>::get_sz(); ++i) {
        if (tarr0.data[i] == tarr1.data[i]) continue;
        if (tarr0.data[i] < tarr1.data[i]) return true;
        if (tarr0.data[i] > tarr1.data[i]) return false;
    }
    return false;
}

template<size_t BYTES> bool operator==(const tarr_type<BYTES> &tarr0, const tarr_type<BYTES> &tarr1) {
    for(size_t i = 0; i < tarr_type<BYTES>::get_sz(); ++i)
        if(tarr0.data[i] != tarr1.data[i])
            return false;
    return true;
}

template<size_t BYTES> bool operator!=(const tarr_type<BYTES> &tarr0, const tarr_type<BYTES> &tarr1) {
    for(size_t i = 0; i < tarr_type<BYTES>::get_sz(); ++i)
        if(tarr0.data[i] != tarr1.data[i])
            return true;
    return false;
}

template<size_t BYTES> bool operator>(const tarr_type<BYTES> &tarr0, const tarr_type<BYTES> &tarr1) {
    for(size_t i = 0; i < tarr_type<BYTES>::get_sz(); ++i) {
        if (tarr0.data[i] == tarr1.data[i]) continue;
        if (tarr0.data[i] > tarr1.data[i]) return true;
        if (tarr0.data[i] < tarr1.data[i]) return false;
    }
    return false;
}

