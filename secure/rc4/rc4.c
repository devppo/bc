#include "rc4.h"

typedef struct rc4_key
{
    unsigned char state[256];
    unsigned char x;
    unsigned char y;
} rc4_key;

#define swap_byte(x,y) t = *(x); *(x) = *(y); *(y) = t

void prepare_key(const unsigned char *key_data_ptr, const unsigned int key_data_len, rc4_key *key)
{
    unsigned char t;
    unsigned char index1;
    unsigned char index2;
    unsigned char* state;
    short counter;

    state = key->state;
    for(counter = 0; counter < COUNT(key->state); counter++)
        state[counter] = (unsigned char)counter;
    key->x = 0;
    key->y = 0;
    index1 = 0;
    index2 = 0;
    for(counter = 0; counter < COUNT(key->state); counter++)
    {
        index2 = (unsigned char)((key_data_ptr[index1] + state[counter] + index2) & 0xFF);
        swap_byte(&state[counter], &state[index2]);
        index1 = (unsigned char)((index1 + 1) % key_data_len);
    }
}

void rc4(unsigned char *buffer_ptr, const unsigned int buffer_len, rc4_key *key)
{
    unsigned char t;
    unsigned char x;
    unsigned char y;
    unsigned char* state;
    unsigned char xorIndex;
    short counter;

    x = key->x;
    y = key->y;
    state = &key->state[0];
    for(counter = 0; counter < buffer_len; counter++)
    {
        x = (unsigned char)((x + 1) & 0xFF);
        y = (unsigned char)((state[x] + y) & 0xFF);
        swap_byte(&state[x], &state[y]);
        xorIndex = (unsigned char)((state[x] + state[y]) & 0xFF);
        buffer_ptr[counter] ^= state[xorIndex];
    }
    key->x = x;
    key->y = y;
}

void rc4crypt(unsigned char *buffer_ptr, 
        const unsigned int buffer_len, 
        const unsigned char *key_data_ptr, 
        const unsigned int key_data_len) 
{
    rc4_key key = {0};
    prepare_key(key_data_ptr, key_data_len, &key);
    rc4(buffer_ptr, buffer_len, &key);
}
