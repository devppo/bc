#include "ed25519.h"

#include <stdlib.h>
#include <mutex>
#include <time.h>

#include <macro.h>

#ifndef ED25519_NO_SEED

#ifdef _WIN32
#include <windows.h>
#include <wincrypt.h>
#else
#include <stdio.h>
#include <sys/time.h>
#endif

#include <stdint.h>
#include <limits.h>

// Simple RNG implementation in C
// (PCG is a family of simple fast space-efficient statistically good algorithms for random number generation)

// *Really* minimal PCG32 code / (c) 2014 M.E. O'Neill / pcg-random.org
// Licensed under Apache License 2.0 (NO WARRANTY, etc. see website)

#define PCG32_INITIALIZER   { 0x853c49e6748fea9bULL, 0xda3e39cb94b95bdbULL }

static struct pcg32_random_t {
    pcg32_random_t() : gRand(0),
        state(0x853c49e6748fea9bULL),
        inc(0xda3e39cb94b95bdbULL) {
        generate_table();
#ifdef _WIN32
        struct {
            SYSTEMTIME st;
            unsigned int ticks;
            LARGE_INTEGER counter;
            LARGE_INTEGER freq;
        } Times;
        GetSystemTime(&Times.st);
        Times.ticks = GetTickCount();
        QueryPerformanceCounter(&Times.counter);
        QueryPerformanceFrequency(&Times.freq);
        gRand = calculate_crc((unsigned char *)&Times, sizeof(Times));
#else
        struct timeval highT;
        gettimeofday(&highT, nullptr);
        gRand = calculate_crc((unsigned char *) &highT, sizeof(highT));
#endif

        gRand = calculate_crc((unsigned char *) &gRand, sizeof(uint64_t));
    }
    void refresh() {
        time_t t = time(nullptr);

        inc ^= t;
        state ^= t;

        inc ^= gRand;
        state ^= gRand;
    }
    static const uint64_t poly = 0xC96C5795D7870F42;
    time_t gRand;
    uint64_t crc_table[0x100];
    uint64_t state;
    uint64_t inc;
    std::mutex m;
    uint32_t pcg32_random_r()
    {
        m.lock();

        uint64_t oldstate = state;
        // Advance internal state
        state = oldstate * 6364136223846793005ULL + (inc|1);
        // Calculate output function (XSH RR), uses old state for max ILP
        auto xorshifted = ( uint32_t )(((oldstate >> 18u) ^ oldstate) >> 27u);
        auto rot = (uint32_t)(oldstate >> 59u);
        auto result = (xorshifted >> rot) | (xorshifted << (( INT_MAX - rot + 1 ) & 31));

        m.unlock();

        return result;
    }
    void generate_table()
    {
        for(size_t i = 0; i < COUNT(crc_table); ++i)
        {
            uint64_t crc = i;

            for(size_t j = 0; j < 8; ++j)
            {
                // is current coefficient set?
                if(crc & 1)
                {
                    // yes, then assume it gets zero'd (by implied x^64 coefficient of dividend)
                    crc >>= 1;

                    // and add rest of the divisor
                    crc ^= poly;
                }
                else
                {
                    // no? then move to next coefficient
                    crc >>= 1;
                }
            }

            crc_table[i] = crc;
        }
    }
    uint64_t calculate_crc(unsigned char *stream, size_t n)
    {

        uint64_t crc = 0;

        for(size_t i = 0; i < n; ++i)
        {
            unsigned char index = stream[i] ^ crc;
            uint64_t lookup = crc_table[index];

            crc >>= 8;
            crc ^= lookup;
        }

        return crc;
    }
} pcg32_random;

int ed25519_create_seed(unsigned char *seed, const size_t seed_sz)
{
    if(seed_sz != seed_type::get_sz()) return -1;
    pcg32_random.refresh();

    for ( size_t i = 0; i < seed_type::get_sz(); i += sizeof(uint32_t)	 )
    {
        uint32_t r = pcg32_random.pcg32_random_r();
        
        seed[i + 0] = (unsigned char)(r & 0xFF);
        seed[i + 1] = (unsigned char)((r >> 8) & 0xFF);
        seed[i + 2] = (unsigned char)((r >> 16) & 0xFF);
        seed[i + 3] = (unsigned char)((r >> 24) & 0xFF);
    }
    
    return 0;
}

#endif
