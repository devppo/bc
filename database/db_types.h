#pragma once

#include <stdlib.h>
#include <stdint.h>

#include "common/types.h"
#include "crypto.h"

#define SALT_SZ 0x20
typedef tarr_type<SALT_SZ> salt_type;

#pragma pack(push, 1)
typedef struct Amount {
    uint32_t high; // integral
    uint64_t low; // fraction
    Amount();
    Amount(uint32_t h, uint64_t l);
    Amount(int32_t h, int64_t l) = delete;
    bool operator < (const Amount &a);
    bool operator > (const Amount &a);
    bool operator != (const Amount &a);
    bool operator == (const Amount &a);
    Amount &operator = (const Amount &a);
    Amount operator + (const Amount &a);
    Amount operator - (const Amount &a);
    Amount operator -= (const Amount &a);
    Amount operator += (const Amount &a);
    double get_low_len();
    Amount get_fee();
} *PAmount;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BalanceRequest {
    public_type pub;
} *PBalanceRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BalanceAnswer {
    public_type pub;
    Amount balance;
} *PBalanceAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct Counter {
    uint64_t blocks_counter;
    uint64_t transactions_counter;
	uint64_t bindata_counter;
    Counter() : blocks_counter(0), transactions_counter(0),bindata_counter(0) {}
} *PCounter;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct Blocks {
    uint64_t offset;
	//TODO: don't need uint64_t? replace to uint32_t
    uint16_t limit;
    Blocks() : offset(0), limit(~(uint16_t)0) {}
} *PBlocks;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BlocksAnswer {
    uint64_t offset;
    uint16_t limit;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    hash_type hashes[0];
#pragma GCC diagnostic pop
    BlocksAnswer() : offset(0), limit(~(uint16_t)0) {}
} *PBlocksAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct BlockSize {
    hash_type block_hash;
    uint32_t tran_size;
	uint32_t bin_size;
	BlockSize() : tran_size(0), bin_size(0) {}
} *PBlockSize;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct Transaction {
    sign_type signature;
    public_type sender_public;
    public_type receiver_public;
    Amount amount;
    char currency[0x10];
    salt_type salt;

    Transaction() { ZEROARR(currency); }
    bool valid() {
    	hash_type hash((unsigned char *)this + 64, 124);
        return signature.check(hash.data, hash_type::get_sz(), sender_public);
    }
    void sign(const unsigned char *priv_buf) {
    	private_type &priv = *(private_type *)priv_buf;
    	hash_type hash((unsigned char *)this + 64, 124);
    	signature.apply(hash.data, hash_type::get_sz(), sender_public, priv);
    }
} *PTransaction;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TransactionsRequest {
    hash_type block_hash;
    uint64_t offset;
    uint16_t limit;
    TransactionsRequest() : offset(0), limit(~(uint16_t)0) {}
} *PTransactionsRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct FeeRequest {
	Amount amount;
} *PFeeRequest;
#pragma pack(pop)

#pragma pack(push, 1)
struct BinaryDataRequest {
	hash_type block_hash;
	unsigned short id_onblock = 0;
};
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	hash_type block_hash;
	unsigned short id_onblock;
	unsigned int offset;
	unsigned int sz;
} BinaryPartRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct {
	hash_type block_hash;
	unsigned short id_onblock;
	unsigned int offset;
	unsigned int sz;
	unsigned char data[0];
} BinaryPartAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TransactionsAnswer {
	union {
		hash_type block_hash;
		struct {
			uint64_t offset;
			uint16_t limit;
		} trn_count{};
	};
	//Transaction transactions[0];
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	sign_type transaction_signs[0];
#pragma GCC diagnostic pop
} *PTransactionsAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TransactionsByKeyAnswer {
	union {
		hash_type block_hash;
		struct {
			uint64_t offset;
			uint16_t limit;
		} trn_count{};
	};
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
	Transaction transactions[0];
#pragma GCC diagnostic pop
} *PTransactionsByKeyAnswer;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TransactionRequest {
    hash_type block_hash;
    sign_type transaction_signature;
} *PTransactionRequest;
#pragma pack(pop)

#pragma pack(push, 1)
typedef struct TransactionAnswer {
    hash_type block_hash;
    Transaction transaction;
} *PTransactionAnswer;
#pragma pack(pop)
