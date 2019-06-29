#include "block_type.h"
size_t BLOCK_META::getMemSize() {
	return data_sz;
}

void BLOCK_META::clear_buffer(hash_type &initial_hash) {
	// TODO: проверять, что память под буфер выделена,
	// чтобы не возникало ошибок с использованием clear_buffer до factory.
	block_ptr->header.bt = btPreviousHash;
	block_ptr->header.sz = (uint32_t)hash_type::get_sz();
	memcpy(block_ptr->Data, initial_hash.data, hash_type::get_sz());
	data_sz = sizeof(BLOCK_HEADER) + block_ptr->header.sz;
}

bool BLOCK_TYPE::valid() {
    bool b_previous = false;
    for(PBLOCK_TYPE current = this;;current = (PBLOCK_TYPE)(&current->Data[current->header.sz])) {
        switch(current->header.bt)
        {
            case btTerminating:
                return b_previous;
            case btInvalid:
                return false;
            case btPreviousHash:
                if(b_previous)
                    return false;//Previous hash found twice, error
                b_previous = true;
                break;
            case btTransaction:
                break;
            default:
                break;
        }
    }
    return false;
}

size_t BLOCK_TYPE::getBlocksSize() {
    auto n = 0;
    for(PBLOCK_TYPE current = this;;current = (PBLOCK_TYPE)(&current->Data[current->header.sz])) {
        switch(current->header.bt)
        {
            case btTerminating:
                return n;
            case btInvalid:
                n = 0;
                return n;
            case btTransaction:
                n++;
                break;
            default:
                break;
        }
    }
    return n;
}

std::list<Transaction> BLOCK_TYPE::getTransactions(uint64_t offset, uint16_t limit) {
    std::list<Transaction> result;
    uint64_t n = 0;
    for(PBLOCK_TYPE current = this;;current = (PBLOCK_TYPE)(&current->Data[current->header.sz])) {
        if(result.size() == limit)
            break;
        switch(current->header.bt)
        {
            case btTerminating:
                return result;
            case btInvalid:
                result.clear();
                return result;
            case btTransaction:
                if(n >= offset) {
                    auto p = (PTransaction)current->Data;
                    result.push_back(*p);
                }
                n++;
                break;
            default:
                break;
        }
    }
    return result;
}

std::shared_ptr<Transaction> BLOCK_TYPE::getTransaction(hash_type &hash) {
    for(PBLOCK_TYPE current = this;;current = (PBLOCK_TYPE)(&current->Data[current->header.sz])) {
        switch(current->header.bt)
        {
            case btTerminating:
                return nullptr;
            case btInvalid:
                return nullptr;
            case btTransaction: {
                hash_type current_hash;
                if(blake2(current_hash.data, hash_type::get_sz(), current->Data, current->header.sz, nullptr, 0)) {
                    if(current_hash == hash) {
                        auto result = std::shared_ptr<Transaction>(new Transaction());
                        *result.get() = *(Transaction *)current->Data;
                        return result;
                    }
                }
                break;
            }
            default:
                break;
        }
    }
    return nullptr;
}

std::shared_ptr<hash_type> BLOCK_TYPE::getPreviousHash() {
    for(PBLOCK_TYPE current = this;;current = (PBLOCK_TYPE)(&current->Data[current->header.sz])) {
        switch(current->header.bt)
        {
            case btTerminating:
                return nullptr;
            case btInvalid:
                return nullptr;
            case btPreviousHash:
            {
                auto result = std::shared_ptr<hash_type>(new hash_type());
                *result.get() = *(hash_type *)current->Data;
                return result;
            }
            default:
                break;
        }
    }
    return nullptr;
}

bool BLOCK_META::close_block() {
	const auto c_sz = getMemSize(); //< текущий размер блока
	auto last_record = (PBLOCK_TYPE)(block_ptr.get()->getBlob() + c_sz);
	last_record->header.bt = btTerminating;
	last_record->header.sz = 0;
	data_sz += sizeof(BLOCK_HEADER);
	logger.dbg("Block have been closed with transaction count: %d", -1);
	return true;
}

//bool BLOCK_META::append_transaction(Transaction &transaction) {
//    const auto c_sz = getMemSize(); //< текущий размер блока
//	// Указатель на начало последней записи
//    auto insert_place = (PBLOCK_TYPE)(block_ptr.get()->getBlob() + c_sz);
//	// TODO: добавить проверку на выход за пределы буфера
//    insert_place->header.bt = btTransaction;
//    insert_place->header.sz = sizeof(Transaction);
//	*(PTransaction)insert_place->Data = transaction;
//    //memcpy(insert_place->Data, &transaction, sizeof(Transaction));
//    data_sz += sizeof(BLOCK_HEADER) + sizeof(Transaction);
//	return true;
//}

bool BLOCK_META::append_data(unsigned char * data, BlockTypes data_type, unsigned int insdata_sz) {
	switch (data_type) {
	case BlockTypes::btTransaction: {
		const auto c_sz = getMemSize();
		auto insert_place = (PBLOCK_TYPE)(block_ptr.get()->getBlob() + c_sz);
		insert_place->header.bt = btTransaction;
		insert_place->header.sz = sizeof(Transaction);
		PTransaction t = (Transaction *)data;
		*(PTransaction)insert_place->Data = *t;
		data_sz += sizeof(BLOCK_HEADER) + sizeof(Transaction);
		break;
	}
	case BlockTypes::btBinaryData: {
		if (!data_sz) return false;
		const auto c_sz = getMemSize();
		auto insert_place = (PBLOCK_TYPE)(block_ptr.get()->getBlob() + c_sz);
		//TODO: сделать проверку, что data_sz <= свободного места
		insert_place->header.bt = BlockTypes::btBinaryData;
		insert_place->header.sz = insdata_sz;
		memcpy(insert_place->Data, data, insdata_sz);
		data_sz += sizeof(BLOCK_HEADER) + insdata_sz;
		break;
	}
	default:
		return false;
	}
	return true;
}

hash_type BLOCK_META::getHash() {
    auto data = (unsigned char *)&block_ptr.get()->header;
    auto sz = getMemSize();
    if(sz != (~(size_t )0)) {
        hash_type result;
        if(blake2(result.data, hash_type::get_sz(), data, sz, nullptr, 0) == 0) {
            return result;
        }
    }
    return hash_type();
}

/*
 * Выделяет память под новый блок и возвращает указатель на этот блок.
 * Помещает в блок информацию о хеще предыдущего блока и терминальный элемент
 *
 * Терминирующая запись добавляется в блок при его закрытии.
 */
BLOCK_META BLOCK_TYPE::create(hash_type &initial_hash) {
	// TODO: реализовать динамически расширяемый буфер. На данный момент 10к tr/bl
    const auto c_initial_sz = sizeof(BLOCK_HEADER) /* previous hash header */ +
            hash_type::get_sz() /* previous hash */ +
            sizeof(Transaction) * 10000 +
            sizeof(BLOCK_HEADER) /* Terminating record */;
	BLOCK_PTR result((PBLOCK_TYPE)new unsigned char[c_initial_sz],
                     [](PBLOCK_TYPE p){ delete[]((unsigned char *)(p)); });

    // Первой записью блока является указание хэша предыдущего блока
    auto pNew = result.get();
    pNew->header.bt = btPreviousHash;
    pNew->header.sz = (uint32_t)hash_type::get_sz();
    memcpy(pNew->Data, initial_hash.data, hash_type::get_sz());
	BLOCK_META meta;
	meta.block_ptr = result;
	meta.buffer_sz = c_initial_sz;
	meta.data_sz = sizeof(BLOCK_HEADER) + hash_type::get_sz();
    return meta;
}

