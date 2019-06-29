#pragma once

#include <stdlib.h>
#include <list>
#include <memory>


#include <common/types.h>
#include <common/macro.h>
#include <common/defs.h>
#include "db_types.h"
#include <map>

enum BlockTypes : int16_t {
    btInvalid = -1,
    btTerminating = 0,
    btTransaction,
    btPreviousHash,
	btBinaryData,

    btCount
};

//#define UNIQUE_OPENED_BLOCK

#pragma pack(push, 1)
typedef struct BLOCK_HEADER {
    BlockTypes bt;
    uint32_t sz;
} BLOCK_HEADER;
#pragma pack(pop)

typedef struct BLOCK_TYPE *PBLOCK_TYPE, *HBLOCK_TYPE;
#ifdef UNIQUE_OPENED_BLOCK
typedef std::unique_ptr<BLOCK_TYPE, std::function<void(PBLOCK_TYPE)>> BLOCK_PTR;
#else
typedef std::shared_ptr<BLOCK_TYPE> BLOCK_PTR;
struct BLOCK_META;
#endif

#pragma pack(push, 1)
typedef struct BLOCK_TYPE {
private:
	friend struct BLOCK_META;
    BLOCK_HEADER header;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
    unsigned char Data[0];
#pragma GCC diagnostic pop
public:
    bool valid();
    const unsigned char *getBlob() { return (const unsigned char *)&header; }
    const unsigned char *get_data() { return (const unsigned char *)Data; }

    size_t getBlocksSize();
    std::list<Transaction> getTransactions(uint64_t offset, uint16_t limit);
    std::shared_ptr<Transaction> getTransaction(hash_type &hash);
    std::shared_ptr<hash_type> getPreviousHash();
    uint32_t get_data_size() {return header.sz;}
    BlockTypes get_type() {return header.bt;}

    static BLOCK_META create(hash_type &initial_hash);
} *PBLOCK_TYPE, *HBLOCK_TYPE;
#pragma pack(pop)

struct BLOCK_META {
public:
	BLOCK_PTR block_ptr;
	size_t getMemSize();
	void clear_buffer(hash_type &initial_hash);
	hash_type getHash();
	bool close_block();
	//bool append_transaction(Transaction &transaction);
	bool append_data(unsigned char * data, BlockTypes data_type = BlockTypes::btTransaction, unsigned int insdata_sz = 0);
	size_t data_sz = 0;
	size_t buffer_sz = 0;
};

struct META_INFO {
public:
	hash_type own_hash;
	hash_type prev_hash;
	std::map<public_type, Amount> out_deltas;
	std::map<public_type, Amount> in_deltas;
};


