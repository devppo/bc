#include "database.h"

#ifdef _WIN32
#include <Windows.h>
#endif
const char *cReadMe = "IMPORTANT:\nDo not do any file operations in this directory else database will corrupt\n";
//------------------------------------------------------------------------------
const char *extract_key_fname(const char *key_path) {
    if(!key_path) return nullptr;
    auto c_req_len = sizeof(key_type) << 1;
    auto c_len = strlen(key_path);
    if(c_len < c_req_len) {
        return nullptr;
    }
    const char *key_fname = key_path + c_len - c_req_len;
    if(c_len != c_req_len) {
#ifdef WIN32
        if((*PRED(key_fname) != '/') && (*PRED(key_fname) != '\\'))
            return nullptr;
#else
        if(*PRED(key_fname) != '/')
            return nullptr;
#endif
    }
    if(strchr(key_fname, '/')) return nullptr;
#ifdef WIN32
    if(strchr(key_fname, '\\')) return nullptr;
#endif
    return key_fname;
}
//------------------------------------------------------------------------------
bool DbHandler::hashExists(key_type hash, bool inchain) {
	if (inchain) {
		const char sql_p[] = "SELECT id FROM chain_cashe WHERE ownhash='%s'";
		char sql_e[sizeof(sql_p) + 200] = { '\0' };		
		char hashstr[200] = { '\0' };
		bool ret = false;
		sqlite3_stmt* stmt = nullptr;
		hash.to_hex(hashstr, 200);
		sprintf(sql_e, sql_p, hashstr);
		if (sqlite3_prepare_v2(sql_handler, sql_e, -1, &stmt, nullptr) == SQLITE_OK)
		{
			if (sqlite3_step(stmt) == SQLITE_ROW)
				ret = true;
			sqlite3_finalize(stmt);
		}
		return ret;		
	}
	std::string fullPart;
	if (getDbRecordPath(hash, sizeof(key_type), DbName, fullPart)) {
		return fileExists(fullPart.c_str());		
	}
	else
		return false;
}

bool DbHandler::initDbDirectory(const std::string &db_name,
	std::string &fullDbPath,
	char *Status,
	size_t StatusSz)
{
	SILENCE
	char db_fname[0x400] = {0};
	sprintf(db_fname, "%s%s%s", HOMEDIR, "/.", db_name.c_str());
	fullDbPath = std::string();

	if (fileExists(db_fname)) {
		SPRINTF(Status, "%s is not directory", db_fname);
		logger.err("%s is not directory", db_fname);
		return false;
	}
	if (!dirExists(db_fname)) {
#ifdef _WIN32
		if (CreateDirectoryA(db_fname, nullptr)) {
			SetFileAttributesA(db_fname, FILE_ATTRIBUTE_HIDDEN);
			saveBufferToFile((std::string(db_fname) + std::string("/READ.ME")).c_str(),
				(unsigned char *)cReadMe,
				(size_t)strlen(cReadMe));
		}
		else {
			SPRINTF(Status, "Directory %s creation error 0x%08X", db_fname, GetLastError());
			logger.err("Directory %s creation error 0x%08X", db_fname, GetLastError());
			return false;
		}
#else
		switch (int md_rc = mkdir(db_fname, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
		{
		case 0:
			saveBufferToFile((std::string(db_fname) + std::string("/READ.ME")).c_str(),
				(unsigned char *)cReadMe,
				(size_t)strlen(cReadMe));
			SPRINTF(Status, "%s initialized successfully", db_name.c_str());
			break;
		case EACCES:
			SPRINTF(Status, ACCESS_ERR);
			return false;
		case ENOENT:
			SPRINTF(Status, "DB path %s invalid", db_fname);
			return false;
		default:
			SPRINTF(Status, INTERNAL_ERR, md_rc);
			return false;
		}
#endif
	}
	std::string db_str = (std::string(db_fname) + std::string("/.KEYS"));
	if (!dirExists(db_str.c_str())) {
#ifdef _WIN32
		if (!CreateDirectoryA(db_str.c_str(), nullptr)) {
			SPRINTF(Status, "Directory %s creation error 0x%08X", db_str.c_str(), GetLastError());
			logger.err("Directory %s creation error 0x%08X", db_str.c_str(), GetLastError());
			return false;
		}
#else
		switch (int md_keys_rc = mkdir(db_str.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
		{
		case 0:
			break;
		case EACCES:
			SPRINTF(Status, ACCESS_ERR);
			return false;
		case ENOENT:
			SPRINTF(Status, "DB path %s invalid", db_fname);
			return false;
		default:
			SPRINTF(Status, INTERNAL_ERR, md_keys_rc);
			return false;
		}
#endif // _WIN32
	}
	db_str= (std::string(db_fname) + std::string("/.EXT"));
	if (!dirExists(db_str.c_str())) {
#ifdef _WIN32
		if (!CreateDirectoryA(db_str.c_str(), nullptr)) {
			SPRINTF(Status, "Directory %s creation error 0x%08X", db_str.c_str(), GetLastError());
			logger.err("Directory %s creation error 0x%08X", db_str.c_str(), GetLastError());
			return false;
		}
#else
		switch (int md_keys_rc = mkdir(db_str.c_str(), S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH))
		{
		case 0:
			break;
		case EACCES:
			SPRINTF(Status, ACCESS_ERR);
			return false;
		case ENOENT:
			SPRINTF(Status, "DB path %s invalid", db_fname);
			return false;
		default:
			SPRINTF(Status, INTERNAL_ERR, md_keys_rc);
			return false;
		}
#endif // _WIN32
	}
	fullDbPath = std::string(db_fname);
	return true;
}


bool DbHandler::getDbRecordPath(const key_type key,
	const size_t key_sz,
	const std::string &db_name,
	std::string &fullRecordPath,
	char *Status,
	size_t StatusSz)
{
    SILENCE

    CHECK_NULL("Key data", key.data);
    CHECK_NULL("DB FileName", db_name.c_str());
    CHECK_TYPE_SZ(key_sz, "Key data", key_type);

    char hex[SUCC(sizeof(key_type) << 1)] = {'\0'};
    if(key.to_hex(hex, COUNT(hex))) {
        char fname[0x400];
        sprintf(fname, "%s%s%s/%s", HOMEDIR, "/.", db_name.c_str(), hex);
        fullRecordPath = std::string(fname);
        return true;
    } else {
        logger.err("key_type::to_hex error");
    }

    return false;
}

bool DbHandler::getDbRecordPattern(const key_type key,
                                    const size_t key_sz,
	std::string &Pattern,
                                    char *Status,
                                    size_t StatusSz)
{
    SILENCE

    CHECK_NULL("Key data", key.data);

    if(key_sz > sizeof(key_type)) {
        SPRINTF(Status,
                "Size of key pattern is more than %zu bytes",
                sizeof(key_type));
        return false;
    }

    char hex[SUCC(sizeof(key_type) << 1)] = {'\0'};
    if(key.to_hex(hex, COUNT(hex), key_sz)) {
        if(key_sz < sizeof(key_type)) {
            char *hex_end = &hex[key_sz << 1];
            memset(hex_end, '?', (sizeof(key_type) - key_sz) << 1);
            hex[sizeof(key_type) << 1] = '\0';
        }
        Pattern = std::string(hex);
        return true;
    }

    return false;
}

bool DbHandler::init(const char *db_name,
                         char *Status,
                         size_t StatusSz)
{
    SILENCE

    DbName = std::string();
    db_initialized = initDbDirectory(std::string(db_name), DbPath, Status, StatusSz);
    if(db_initialized) db_initialized = loadKeys(Status, StatusSz);
	if (db_initialized) {
		setSql();
		state_own_lasthash();
		load_balances_sql();
	}
    if(!db_initialized) {
    	SPRINTF(Status, "DB not initialized");
    	return false;
    }

    DbName = std::string(db_name);
    return true;
}

bool DbHandler::setSql() {
    const std::string sql_path = DbPath + std::string("/.EXT/ext.db");
    if(sqlite3_open(sql_path.c_str(), &sql_handler) != SQLITE_OK) {
        logger.err("SQLite database %s open error", sql_path.c_str(), sqlite3_errmsg(sql_handler));
        return false;
    }
    char *sql_err = nullptr;
    const char *table_list[] = {
            SQL_INIT_HOSTS_TABLE,
            SQL_INIT_BALANCES_TABLE,
			//SQL_INIT_BALANCES_INDEX,
            SQL_INIT_TRS_PERSONAL_TABLE,
            nullptr
    };
    const char **curr_sql = table_list;
    while(*curr_sql) {
        if (sqlite3_exec(sql_handler, *curr_sql, nullptr, nullptr, &sql_err) != SQLITE_OK) {
            logger.err("SQLite database %s tables initialization error", sql_err);
            sqlite3_free(sql_err);
            sqlite3_close(sql_handler);
            sql_handler = nullptr;
            return false;
        }
        ++curr_sql;
    }
    return true;
}

bool DbHandler::setKeys(const public_type &pub_key,
        const private_type &priv_key)
{
    const std::string pub_path = DbPath + std::string("/.KEYS/public.key");
    const std::string priv_path = DbPath + std::string("/.KEYS/private.key");

    if(fileExists(pub_path.c_str())) return false;
    if(fileExists(priv_path.c_str())) return false;
    memcpy(public_key.data, pub_key.data, sizeof(public_type));
    memcpy(private_key.data, priv_key.data, sizeof(private_type));

    return saveBufferToFile(pub_path.c_str(), public_key.data, sizeof(public_type)) &&
        saveBufferToFile(priv_path.c_str(), private_key.data, sizeof(private_type));
}

bool DbHandler::loadKeys(char *Status,
                             size_t StatusSz)
{
    SILENCE

    const std::string pub_path = DbPath + std::string("/.KEYS/public.key");
    const std::string priv_path = DbPath + std::string("/.KEYS/private.key");
    size_t priv_key_sz;
    if(unsigned char *priv =
            loadBufferFromFile(
                    priv_path.c_str(),
                    priv_key_sz))
    {
        if(priv_key_sz != sizeof(private_type)) {
            SPRINTF(Status, "Private key corrupt");
            delete[] priv;
            return false;
        }
        memcpy(private_key.data, priv, sizeof(private_type));
    } else {
        SPRINTF(Status, "Private key not found");
        return false;
    }
    size_t pub_key_sz;
    if(unsigned char *pub =
            loadBufferFromFile(
                    pub_path.c_str(),
                    pub_key_sz))
    {
        if(pub_key_sz != sizeof(public_type)) {
            SPRINTF(Status, "Public key corrupt");
            delete[] pub;
            return false;
        }
        memcpy(public_key.data, pub, sizeof(public_type));
    } else {
        SPRINTF(Status, "Public key not found");
        return false;
    }
    return true;
}

bool DbHandler::init(const char *db_name,
                         const public_type &pub,
                         const private_type &priv,
                         char *Status,
                         size_t StatusSz)
{
    SILENCE

    SPRINTF(Status, "%s", db_name);
    DbName = std::string();
    db_initialized = initDbDirectory(std::string(db_name), DbPath, Status, StatusSz) &&
            setKeys(pub, priv) && setSql();
	if (db_initialized) {
		state_own_lasthash();
		load_balances_sql();
	} else
     return false;
    //DB_INITIALIZED

    DbName = std::string(db_name);
    return true;
}

bool DbHandler::initialized() {
    return db_initialized;
}

bool DbHandler::deinit(char *Status,
                           size_t StatusSz)
{
    SILENCE

    if(sql_handler) {
        sqlite3_db_cacheflush(sql_handler);
        sqlite3_close(sql_handler);
        sql_handler = nullptr;
    }
    if(db_initialized) {
		SPRINTF(Status, "Database deinitialized");
	}
    else {
    	SPRINTF(Status, "Database handler was not initialized");
	}
	db_initialized = false;
    return true;
}

bool DbHandler::obtain(const unsigned char *pkey,
        const size_t key_sz,
        unsigned char *&pdata,
        size_t &data_sz,
        LoadMode lm,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    DB_INITIALIZED

    CHECK_NULL("Key data", pkey)
    CHECK_TYPE_SZ(key_sz, "Key data", key_type)

		std::string fname;
    auto hkey = (key_type *)pkey;
    auto rec_ptr = get_loaded(*hkey);
    if(rec_ptr != nullptr) {
        pdata = rec_ptr->getData();
        data_sz = rec_ptr->getDataSz();
        return true;
    }
    if(getDbRecordPath(*hkey, key_sz, DbName, fname, Status, StatusSz)) {
        logger.dbg(fname.c_str());
		std::shared_ptr<DbRecord> record(new DbRecord());
        if(record->setPath(fname)) {
            if(record->load(lm)) {
                auto it_record = records.emplace(*hkey, record);
				pdata = it_record.first->second->getData();
				data_sz = it_record.first->second->getDataSz();
				return true;
            } else {
                SPRINTF(Status, "Loading %s error", record->getPath().c_str());
            }
        } else {
            SPRINTF(Status, "Setting path %s error", fname.c_str());
        }
    } else {
        SPRINTF(Status, "There in database %s is no record", DbName.c_str());
    }
    return false;
}



bool DbHandler::index(const unsigned char* block_buffer, size_t block_sz, META_INFO *metainfoptr) {
	// TODO: проверять выход за пределы блока, ориентироваться на block_sz
	++counter.blocks_counter;
	auto current_record = block_buffer;
	std::map<public_type, iobalance_t> deltas; //< сумма стоимости транзакций (входящие, исходящие)
	//std::map<public_type, Amount> outgoing_deltas; //< сумма стоимости транзакций для отправителей (минус для баланса)
	//std::map<public_type, Amount> incoming_deltas; //< сумма стоимости транзакций для получателей (плюс для баланса)

    bool empty_buffer = false;
    while(!empty_buffer) {
    	auto item = (PBLOCK_TYPE)current_record;
        switch (item->get_type()) {
            case BlockTypes::btTerminating:
                empty_buffer = true;
                break;
            case BlockTypes::btPreviousHash:
				if (metainfoptr) {
					//hash_type ph;
					memcpy((void *)&metainfoptr->prev_hash, (void *)item->get_data(), sizeof(hash_type));
				}
                break;
            case BlockTypes::btTransaction: {
				++counter.transactions_counter;
				auto t = (PTransaction) (item->get_data());

				auto found_delta = deltas.find(t->sender_public);
				if (found_delta == deltas.end()) {
					auto outgoing = std::make_pair(t->sender_public, iobalance_t{Amount{}, t->amount});
					deltas.emplace(outgoing);
				} else {
					found_delta->second.outgoing += t->amount;
				}

				found_delta = deltas.find(t->receiver_public);
				if (found_delta == deltas.end()) {
					auto incoming = std::make_pair(t->receiver_public, iobalance_t{t->amount, Amount{}});
					deltas.emplace(incoming);
				} else {
					found_delta->second.incoming += t->amount;
				}

				break;
			}
			case BlockTypes::btBinaryData: {
				++counter.bindata_counter;
				break;
				
			}
        	default:
        		break;
        }
        auto step = sizeof(BLOCK_HEADER) + item->get_data_size();
		current_record += step;
    }

    size_t processed_bytes = current_record - block_buffer;
    if(processed_bytes != block_sz) {
		logger.warn("index: processed bytes = %zu (expected = %zu)", processed_bytes, block_sz);
    	return false; // Обработано неверное количество байт
    }

    for (auto d : deltas) {
    	auto i = balances.find(d.first);
    	if (i == balances.end()) {
    		balances.emplace(d);
    	}
    	else {
    		i->second.incoming += d.second.incoming;
    		i->second.outgoing += d.second.outgoing;
			
    	}
    }

	//for (auto d : deltas) {
	//	auto s = balances.find(d.first);
	//	if (s != balances.end());
	//		//save_balance_any((public_type *)&(s->first), &(s->second));
	//}

	return true;
}

bool DbHandler::insert(const unsigned char *pkey,
        const size_t key_sz,
        const unsigned char *pdata,
        const size_t data_sz,
        LoadMode lm,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    DB_INITIALIZED

    CHECK_NULL("Data", pdata)
    CHECK_SZ_LESS(data_sz, sizeof(sign_type), "Data")

	std::string fname;
    auto hkey = (key_type *)pkey;
    logger.dbg("insert: %d bytes key size", key_sz);
    char buff[0x100] = {'\0'};
    (*(key_type *)pkey).to_hex(buff, COUNT(buff));
    logger.dbg("insert: %s key hex", buff);

    if(getDbRecordPath(*hkey, key_sz, DbName, fname, Status, StatusSz)) {

        if(fileExists(fname.c_str())) {
        	auto key_fname = extract_key_fname(fname.c_str());

            SPRINTF(Status, "Record %s already exists", key_fname);
            logger.warn("Record %s already exists", key_fname);
			if (this->hSync.SyncState() == SyncHandler::eSyncLanch)
				this->hSync.set_EntityReceived(*hkey);
            return false;
        }
        //TODO: sync
		if (this->hSync.SyncState() == SyncHandler::eSyncLanch) {
			sockaddr_in undefaddr{};
			ZEROIZE(&undefaddr);
			auto item = (PBLOCK_TYPE)pdata;
			if ((item->get_type() == BlockTypes::btPreviousHash) && (item->get_data_size() == sizeof(key_type))) {
				auto prevH = (key_type *) item->get_data();
				if (!prevH->empty())
				{
					if (!hashExists(*prevH)) {
						hSync.append(*prevH, undefaddr);
						logger.dbg("SYNC: new hash append: %s", buff);
					}
				}
			}
		}
        if(saveBufferToFile(fname.c_str(), pdata, data_sz, Status, StatusSz)) {
			if (this->hSync.SyncState() == SyncHandler::eSyncLanch)
			{
				hSync.set_EntityReceived(*hkey);
				logger.dbg("SYNC: Entity received mark added: %s", extract_key_fname(fname.c_str()));
			}
			std::shared_ptr<DbRecord> record(new DbRecord());
            if(record->setPath(fname)) {
                if(record->load(lm)) {
                    records.emplace(*hkey, record);
                    SPRINTF(Status, "Record %s inserted to database", extract_key_fname(fname.c_str()));
                    return true;
                }
            }
			
        }
    } else {
        logger.err("getDbRecordPath: %s", fname.c_str());
    }

    return false;
}

bool DbHandler::del(const unsigned char *pkey,
         const size_t key_sz,
         char *Status,
                        size_t StatusSz)
{
    SILENCE

    DB_INITIALIZED

		std::string fname;
    auto hkey = (key_type *)pkey;
    if(getDbRecordPath(*hkey, key_sz, DbName, fname, Status, StatusSz)) {
        unload(*hkey);
        int err = std::remove(fname.c_str());
        SPRINTF(Status, "Record remove %s", err ? "error" : "success");
        return !err;
    }

    return false;
}

std::list<std::string> DbHandler::enumerate(unsigned char *pkey,
                                                size_t key_sz,
                                                LoadMode lm,
                                                const size_t offset,
                                                const size_t limit,
                                                char *Status,
                                                size_t StatusSz)
{
    SILENCE

	std::list<std::string> result;
    if(db_initialized) {
		std::string fullPatternPath;
        auto hkey = (key_type *)pkey;
        if(getDbRecordPattern(*hkey, key_sz, fullPatternPath, Status, StatusSz)) {
            result = list_directory(fullPatternPath, DbPath, sfFilesOnly, offset, limit, Status, StatusSz);
        }
    } else {
        SPRINTF(Status, "Database is not initialized");
    }

    return result;
}

std::list<key_type> DbHandler::enum_keys(unsigned char *pkey,
                                      size_t key_sz,
                                      LoadMode lm,
                                      const size_t offset,
                                      const size_t limit,
                                      char *Status,
                                      size_t StatusSz)
{
    SILENCE

    std::list<key_type> result;
    if(db_initialized) {
		std::string fullPatternPath;
        auto hkey = (key_type *)pkey;
        key_type key;
        if(pkey && key_sz)
            memcpy(key.data, hkey->data, sizeof(key_type));
        if(getDbRecordPattern(key, key_sz, fullPatternPath, Status, StatusSz)) {
			logger.dbg("DB record pattern: %s", fullPatternPath.c_str());

            auto fnames = list_directory(fullPatternPath, DbPath, sfFilesOnly, offset, limit);
            int n = 0;
            for(auto &fname : fnames) {
                key_type cur_key;
                auto c_key_fname = extract_key_fname(fname.c_str());
				logger.dbg("Key filename %s", fname.c_str());
				if(c_key_fname) {
					if (cur_key.from_hex(c_key_fname)) {
						logger.dbg("key loaded from hex %s", c_key_fname);
						result.push_back(cur_key);
						n++;
					} else {
						logger.err("key_type::from_hex from %s", c_key_fname);
					}
				}
            }
            SPRINTF(Status, "%d keys found", n);
        }
    } else {
        SPRINTF(Status, "Database is not initialized");
    }

    return result;
}

size_t DbHandler::enum_del(unsigned char *pkey,
              const size_t key_sz,
              char *Status,
                               size_t StatusSz)
{
    SILENCE
    DB_INITIALIZED
	std::list<std::string> fnames = enumerate(pkey, key_sz, lmEmpty, 0, (~(size_t)0), Status, StatusSz);
    size_t removed = 0;
    for(auto &fname : fnames) {
        // TODO: unload internal record
		removed += !std::remove(fname.c_str());
    }
    return removed;
}

std::shared_ptr<DbHandler::DbRecord> DbHandler::get_loaded(const key_type &key) {
    try {
        return records.at(key);
    } catch(const std::out_of_range& e) {
        return nullptr;
    }
}

bool DbHandler::unload(const key_type &key) {
    bool result = (get_loaded(key) != nullptr);
    if(result) records.erase(key);
    return result;
}

bool DbHandler::full_index() {
	
	counter.blocks_counter = 0;
	counter.transactions_counter = 0;
	balances.clear();
	auto curr_hash = GetLastHash();

	unsigned char *buffer = nullptr;
	size_t sz = 0;
	// перебор всех хешей в базе
	while(!curr_hash.empty()) {
		if(obtain((unsigned char*)&curr_hash, sizeof(hash_type), buffer, sz)) {
			index(buffer, sz);
		}
		if(!getNextHashByChain(curr_hash, &curr_hash)) {
			/*
			auto current_record = buffer;
			for(;;){
				// TODO: Отслеживать выход за предел буфера
				auto item = (PBLOCK_TYPE)current_record;
				if (item->get_type() == btTerminating) {
					break;
				}
				if (item->get_type() == btTransaction) {
					auto t = (PTransaction)(item->get_data());
					issuer_key = t->receiver_public;
					break;
				}
			}
			*/
			return false;
		}
	}
	auto current_record = buffer;
	if(current_record) {
		for (;;) {
			auto item = (PBLOCK_TYPE) current_record;
			if (item->get_type() == btTerminating) {
				break;
			}
			if (item->get_type() == btTransaction) {
				auto t = (PTransaction) (item->get_data());
				issuer_key = t->receiver_public;
				break;
			}
			current_record = (unsigned char*)current_record + sizeof(BLOCK_HEADER) + item->get_data_size();
		}
	}
	save_balances_sql();
	return true;
}

int DbHandler::restore_chain(size_t *chainblcount, size_t *badblcount,  hash_type * curr_lasthash,  hash_type * need_hash, char * Status , int StatusSz) { // восстановление цепочки хешей и запись ее в SQLite
	//restorestatus - result of restore chain: 0 - chain empty; -1 - chain width breaks; -2 chain without first block; 
	//curr_lasthash - last hash in restored chain
	//need_hash - first located break in chain
	// returned: count of chained blocks
	std::list<std::string> fnames = list_directory("*", this->DbPath, sfFilesOnly);
	std::list<std::string> badblocks;
	std::map<hash_type, hash_type> searchQueue;
	std::map<size_t, hash_type> sortedQueue;
	hash_type own_hash;
	hash_type prv_hash;
	hash_type savedlasthash = hash_type();
	int reststatus = 0;
	size_t cntr = 0;
	int bl = 0;
	//size_t badbl = 0;
	char flg_corrupt = 0;
	for (auto f: fnames) {
#ifdef _WIN32
		own_hash.from_hex((char *)f.c_str());
#else
		own_hash.from_hex(basename((char *)f.c_str()));
#endif
		if (getNextHashByChain(own_hash, &prv_hash))
			searchQueue.emplace(std::make_pair(prv_hash, own_hash));
		else {
			logger.err("block %s has no previovs hash!", f.c_str());
			badblocks.emplace_back(f);
		}
	}
	fnames.clear();
	if (searchQueue.empty()) {
		if (Status != nullptr)
			StatusSz = sprintf(Status, "No blocks in chain");
		return 0;
	}
	else {
		// 1st проход - от нулевого хеша
		prv_hash = hash_type();
		while (sortedQueue.size() != searchQueue.size()) {
			auto s = searchQueue.find(prv_hash);
			if (s == searchQueue.end()) {
				if (Status != nullptr)
					StatusSz = sprintf(Status, "Chain is corrupt!");
				flg_corrupt = 1;
				break;
			}
			else {
				own_hash = s->second;
				sortedQueue.emplace(std::make_pair(cntr, own_hash));
				cntr++;
				prv_hash = own_hash;
			}
		}
		// чистка зафиксированных
		if (!sortedQueue.empty()) {
			for (auto f1 : sortedQueue)
				for (auto f2 :searchQueue) 
					if (f2.second == f1.second) 
					{
						searchQueue.erase(f2.first);
						break;
					}
		}
		//запись в SQL 
		sqlite3_stmt* stmt = nullptr;
		
		if (!sortedQueue.empty())
		{
			bl += sortedQueue.size();
			if (sqlite3_exec(sql_handler, "DROP TABLE IF EXISTS chain_cashe", nullptr, nullptr, nullptr) == SQLITE_OK
				&& sqlite3_exec(sql_handler, SQL_INIT_CHAINCASHE_TABLE, nullptr, nullptr, nullptr) == SQLITE_OK) {
				//rc = sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_INSERT,sizeof(SQL_CHAINCASHE_INSERT), &stmt, nullptr);
				sqlite3_exec(sql_handler, "BEGIN;", nullptr, nullptr, nullptr);
				for (size_t i = 0; i < sortedQueue.size(); i++) {
					auto h = sortedQueue.find(i);
					if (h == sortedQueue.end())
						//logger.dbg("CHAIN ERROR! Item %u on %u", i, cntr)
						;
					else {
						char hname[200];
						h->second.to_hex(hname, 200);
						sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_INSERT, sizeof(SQL_CHAINCASHE_INSERT), &stmt, nullptr);
						sqlite3_bind_int(stmt, 1, i);
						sqlite3_bind_text(stmt, 2, hname, -1, SQLITE_STATIC);
						sqlite3_step(stmt);
						if (i == sortedQueue.size() - 1)
							savedlasthash = h->second;
						
					}
				}
				sqlite3_finalize(stmt);			
				sqlite3_exec(sql_handler, "COMMIT;", nullptr, nullptr, nullptr);
			}
			sortedQueue.clear();
		}
		
		//2nd проход - от lasthash

		if (!sortedQueue.empty())
		{
			if (!own_last_hash.empty())
			{
				sortedQueue.clear();
				
				cntr = bl+searchQueue.size();
				own_hash = own_last_hash;
				if (getNextHashByChain(own_hash, &prv_hash))
				{
					sortedQueue.emplace(std::make_pair(cntr--, own_hash));
					savedlasthash = own_hash;
					while (true) 
					{
						own_hash = prv_hash;
						if (!hashExists(own_hash))
						{
							flg_corrupt = -1;
							*need_hash = own_hash;
							break;
						}
						else
						{
							if (!getNextHashByChain(own_hash, &prv_hash))
							{
								flg_corrupt = -1;
								*need_hash = own_hash;
								char fname[200] = { '\0' };
								own_hash.to_hex(fname, 200);
								badblocks.emplace_back(fname);
								break;
							}
							else
								sortedQueue.emplace(std::make_pair(cntr--, own_hash));
						}

					}

				}
				else {
					flg_corrupt = 1;
					*need_hash = own_hash;
				}
			}
			//чистка зафиксированных 2
			if (!sortedQueue.empty()) {
				for (auto f1 : sortedQueue)
					for (auto f2 : searchQueue)
						if (f2.second == f1.second)
						{
							searchQueue.erase(f2.first);
							break;
						}
			}
			if (!sortedQueue.empty())
				for (auto f1 : searchQueue)
				{
					char blname[200] = { '\0' };
					f1.second.to_hex(blname, 200);
					badblocks.emplace_back(blname);
				}
		}
		// сохранение 2 половины
		if (!sortedQueue.empty())
		{
			bl += sortedQueue.size();
			if (sqlite3_exec(sql_handler, SQL_INIT_CHAINCASHE_TABLE, nullptr, nullptr, nullptr) == SQLITE_OK) {
				//rc = sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_INSERT,sizeof(SQL_CHAINCASHE_INSERT), &stmt, nullptr);
				sqlite3_exec(sql_handler, "BEGIN;", nullptr, nullptr, nullptr);
				for (auto h : sortedQueue) {
						char hname[200];
						h.second.to_hex(hname, 200);
						sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_INSERT, sizeof(SQL_CHAINCASHE_INSERT), &stmt, nullptr);
						sqlite3_bind_int(stmt, 1, h.first);
						sqlite3_bind_text(stmt, 2, hname, -1, SQLITE_STATIC);
						sqlite3_step(stmt);						
				}				
				sqlite3_finalize(stmt);
				sqlite3_exec(sql_handler, "COMMIT;", nullptr, nullptr, nullptr);
			}
		}
		if (!savedlasthash.empty()) {			
			*curr_lasthash = savedlasthash;
		}
		if (Status != nullptr) {
			StatusSz = sprintf(Status, "Chain %s, %zu blocks has", flg_corrupt == 0 ? "restored" : "corrupted!", cntr);
		}
		reststatus = flg_corrupt == 0 ? bl : -1;
		//TODO: выводить список badblocks
		sqlite3_exec(sql_handler, "DROP TABLE IF EXISTS badblocks", nullptr, nullptr, nullptr);
		if (!badblocks.empty()) {
			*badblcount = badblocks.size();
			if (sqlite3_exec(sql_handler, "CREATE TABLE IF NOT EXISTS badblocks (blockname TEXT)", nullptr, nullptr, nullptr) == SQLITE_OK) {
				for (const auto& nm : badblocks) {
					sqlite3_prepare_v2(sql_handler, "INSERT INTO badblocks (blockname) VALUES(?)", -1, &stmt, nullptr);
					sqlite3_bind_text(stmt, 1, nm.c_str(), -1, SQLITE_STATIC);
					sqlite3_step(stmt);
				}
				sqlite3_finalize(stmt);
			}
		}

	}
	*chainblcount = bl;
	return reststatus;
}

bool DbHandler::getNextHashByChain(const hash_type& nhash, const hash_type *r_hash) {
	unsigned char *buff = nullptr;
	size_t sz = 0;
	bool retv = false;
	if (obtain((unsigned char*)&nhash, sizeof(hash_type), buff, sz)) {
		bool block_empty = false;
		unsigned char *blk = buff;
		while (!block_empty) {
			auto ptr = (PBLOCK_TYPE)blk;
			switch (ptr->get_type()) {
			case BlockTypes::btTerminating:
				block_empty = true;
				break;
			case BlockTypes::btPreviousHash:
				memcpy((unsigned char *)r_hash, (unsigned char *)ptr->get_data(), sizeof(hash_type));				
				block_empty = true;
				retv = true;
				break;
			default:
				break;
			}
			if (!block_empty)
				blk += sizeof(BLOCK_TYPE);
		}		
	}
	return retv;
}

bool DbHandler::checkIntegrityChain(bool check_valid_hashes, bool force_restorechain) {

#ifdef _WIN32
	time_t tics = GetTickCount();
#endif // _WIN32

	// версия 2, с использованием сохраненной цепочки
	bool needrestore = false;
	hash_type own_hash = hash_type();
	hash_type prv_hash = hash_type();
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	size_t blcount = 0;
	size_t badbl = 0;
	// step 1 получение сохраненной цепочки
	std::map<unsigned int, hash_type> hashChain;
	sqlite3_stmt* stmt = nullptr;
	int rc = sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_SELECT, -1, &stmt, nullptr);
	if (rc == SQLITE_OK) {
		rc = sqlite3_step(stmt);
		while (rc == SQLITE_ROW) {
			auto h_id = sqlite3_column_int(stmt, 0);
			auto hash_str = (unsigned char *)sqlite3_column_text(stmt, 1);
			hash_type hash;
			hash.from_hex((const char *)hash_str);
			hashChain.emplace(std::make_pair(h_id, hash));
			rc = sqlite3_step(stmt);
		}
		sqlite3_finalize(stmt);
	}
	if (!hashChain.empty()) // проверка по сохраненной цепочке
	{
		unsigned int index = 0;
		for (auto f : hashChain) 
		{
			if (f.first != index) {
				needrestore = true;
				break;
			}
			else
				index++;
			if (!getNextHashByChain(f.second, &prv_hash)) {
				needrestore = true;
				break;
			}
			else
			{
				if (f.first == 0)
				{
					if (!prv_hash.empty()) {
						needrestore = true;
						break;
					}
				}
				else
					{
						if (prv_hash != own_hash) {
							needrestore = true;
							break;
						}						
					}
				own_hash = f.second;
				if (check_valid_hashes)
				{
					unsigned char * buffer;
					size_t sz;
					if (obtain((unsigned char *)&f.second, sizeof(hash_type), buffer, sz)) {
						hash_type real_hash;
						if (blake2(real_hash.data, hash_type::get_sz(), buffer, sz, nullptr, 0) == 0) {
							if (real_hash != f.second) {
								needrestore = true;
								del((const unsigned char *)&f.second, hash_type::get_sz());
								break;
							}
						}
					}
				}
			}
		}
		if (own_hash != own_last_hash)
			needrestore = true;
	}
	else 
		needrestore = true;
	blcount = hashChain.size();
	if (needrestore || force_restorechain) {
		int ret = 0;
		sockaddr_in emptyaddr{};
		ZEROIZE(&emptyaddr);
		//do {
			
			hash_type new_lasthash = hash_type();
			hash_type need_hash = hash_type();
			ret = restore_chain(&blcount, &badbl, &new_lasthash, &need_hash, Status, MINIMAL_STATUS_LENGTH);
			if (ret == 0) {
				//база пустая - зачищаем lasthash и выходим 
				own_last_hash = hash_type();				
				std::string c_last_path = DbPath + std::string("/.EXT/last");
				std::remove(c_last_path.c_str());
				logger.dbg("blockhain empty!");
				return true;
			}
			if (new_lasthash != own_last_hash && !new_lasthash.empty())
			{
				own_last_hash = new_lasthash;
				this->dropLastHash();
			}
			if (!need_hash.empty())
			{
				hSync.append(need_hash, emptyaddr);
			}

		//} while (ret <= 0);
			needrestore = ret < 0 ? true : false;
	}
	logger.dbg("BASE %s :check integrity complete,  status: %s, %i blocks, %i badblocks", this->DbName.c_str(),  Status, blcount, badbl);


	return !needrestore;
}
bool DbHandler::getChainIdHash( hash_type * chainid_hash) {
	bool ret = false;
	sqlite3_stmt* stmt = NULL;
	const unsigned char * hashstr;
	*chainid_hash = hash_type();
	if (sqlite3_prepare_v2(sql_handler, "SELECT ownhash FROM chain_cashe WHERE id=0", -1, &stmt, nullptr) == SQLITE_OK) 
	{
		int rc = sqlite3_step(stmt);
		if (rc == SQLITE_ROW || rc == SQLITE_OK) //??
		{
			hashstr = sqlite3_column_text(stmt, 0);
			chainid_hash->from_hex((const char *)hashstr);
			ret = true;
		}
		sqlite3_finalize(stmt);
	}
	return ret;
}

bool DbHandler::appendHash_intochaincashe(hash_type added_hash) {
	sqlite3_stmt* stmt = NULL;
	char hashstr[200] = { '\0' };
	long newid = -1;
	added_hash.to_hex(hashstr, 200);
	auto rc = sqlite3_exec(sql_handler, "BEGIN;", nullptr, nullptr, nullptr);
	if (rc) {
		logger.err("insert hash into cashe FAILED, error %d: %s", rc, sqlite3_errmsg(sql_handler));
		return false;
	}
	if (sqlite3_prepare_v2(sql_handler, "SELECT MAX(id) FROM chain_cashe", -1, &stmt, nullptr) == SQLITE_OK) {
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			newid = sqlite3_column_int64(stmt, 0) + 1;
			sqlite3_prepare_v2(sql_handler, SQL_CHAINCASHE_INSERT, -1, &stmt, nullptr);
			sqlite3_bind_int(stmt, 1, newid);
			sqlite3_bind_text(stmt, 2, hashstr, -1, SQLITE_STATIC);
			sqlite3_step(stmt);
		}
		sqlite3_finalize(stmt);
	}
	sqlite3_exec(sql_handler, "COMMIT;", nullptr, nullptr, nullptr);
	return newid != -1;
}

std::vector<RestoreChainItem> DbHandler::get_chainhashes(hash_type &first) {
	static const char * sql_1 = "SELECT id FROM chain_cashe WHERE ownhash=?";
	static const char * sql_2 = "SELECT MIN(id) FROM chain_cashe";
	const char * sqltxt = first.empty() ? sql_2 : sql_1;
	std::vector<RestoreChainItem> result;
	sqlite3_stmt* stmt = nullptr;
	char first_ch[200] = { '\0' };
	int first_i = 0;
	first.to_hex(first_ch, 200);
	int rc = sqlite3_prepare_v2(sql_handler, sqltxt, - 1, &stmt, nullptr);
	if (rc == SQLITE_OK)
	{
		if (!first.empty())
			sqlite3_bind_text(stmt, 1, first_ch, -1, SQLITE_STATIC);
		if (sqlite3_step(stmt) == SQLITE_ROW) {
			first_i = sqlite3_column_int(stmt, 0);
			sqlite3_finalize(stmt);
			if (!first.empty()) first_i++;
			if (sqlite3_prepare_v2(sql_handler, "SELECT ownhash,id FROM chain_cashe WHERE id >= ? ORDER BY id", -1, &stmt, nullptr) == SQLITE_OK) {
				sqlite3_bind_int(stmt, 1, first_i);
				do {
					rc = sqlite3_step(stmt);
					if (rc == SQLITE_ROW) {
						auto itm = sqlite3_column_text(stmt, 0);
						auto i_num = sqlite3_column_int(stmt, 1);
						hash_type h;			
						h.from_hex((const char *)itm);
						RestoreChainItem ff = { i_num,h };
						result.emplace_back(ff);
					}
				} while (rc == SQLITE_ROW);
				sqlite3_finalize(stmt);
			}
		}
	}
	return result;
}
//bool DbHandler::checkIntegrityChain_oldversion(bool check_valid_hashes) {
//	char hsh_str[200] = { '\0' };
//	sockaddr_in emptyaddr;
//	ZEROIZE(&emptyaddr);
//	hash_type curr_hash = own_last_hash;
//	hash_type prev_hash;
//	//bool filevalid = false;
//	uint16_t chk = 0;
//	if (curr_hash.empty())
//	return true; // если база пустая
//	////do {
//	////	chk++;
//	////	if (!getNextHashByChain((unsigned char *)&curr_hash, sizeof(hash_type), &prev_hash)) { // файл сбойный, требуется запрос
//	////		hSync.bottom_hash =hash_type();
//	////		hSync.top_hash = own_last_hash;
//	////		hSync.append(curr_hash, emptyaddr);
//	////		curr_hash.to_hex(hsh_str, 200);
//	////		del((unsigned char *)&curr_hash, sizeof(hash_type));
//	////		logger.dbg("file %s not valid! sync header activated",hsh_str);
//	////		return false;
//	////	}
//	////	else {
//	////		if (check_valid_hashes) { // если задан пересчет хэшей
//	////			unsigned char * buffer;
//	////			size_t sz;
//	////			if (obtain((unsigned char *)&curr_hash, sizeof(hash_type), buffer, sz)) {
//	////				hash_type real_hash;
//	////				if (blake2(real_hash.data, hash_type::get_sz(), buffer, sz, nullptr, 0) == 0) {
//	////					if (real_hash == curr_hash) {
//	////						// TODO: совпадают хэши, все верно
//	////					}
//	////					else {
//	////						hSync.bottom_hash = hash_type();
//	////						hSync.top_hash = own_last_hash;
//	////						hSync.append(curr_hash, emptyaddr);
//	////						curr_hash.to_hex(hsh_str, 200);
//	////						del((unsigned char *)&curr_hash, sizeof(hash_type));
//	////						logger.dbg("file %s have not equal real hash! sync header activated", hsh_str);
//	////						return false;
//	////					}
//	////				}
//	////				else {
//	////					hSync.bottom_hash = hash_type();
//	////					hSync.top_hash = own_last_hash;
//	////					hSync.append(curr_hash, emptyaddr);
//	////					curr_hash.to_hex(hsh_str, 200);
//	////					del((unsigned char *)&curr_hash, sizeof(hash_type));
//	////					logger.dbg("file %s error calc hash! sync header activated", hsh_str);
//	////					return false;
//	////				}
//	////			}
//	////		}
//	////		if (!hashExists(prev_hash) && !(prev_hash.empty())) { // если нет предыдущего и он не последний
//	////			hSync.bottom_hash = hash_type();
//	////			hSync.top_hash = own_last_hash;
//	////			hSync.append(prev_hash, emptyaddr);
//	////			prev_hash.to_hex(hsh_str, 200);
//	////			logger.dbg("file %s not found! sync header activated", hsh_str);
//	////			return false;
//	////		}			
//	////	}
//	////	curr_hash = prev_hash;
//	////} while (!prev_hash.empty());
//	// восстановление цепочки хешей
//	// TODO: сделать опционально (?)
//	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
//	size_t blcount = 0;
//	size_t badbl = 0;
//	hash_type new_lasthash=hash_type();
//	hash_type need_hash = hash_type();
//	int ret = restore_chain(&blcount, &badbl, &new_lasthash, &need_hash, Status, MINIMAL_STATUS_LENGTH);
//	//restore_chain(Status,MINIMAL_STATUS_LENGTH);
//	logger.dbg("BASE %s :check integrity complete, code: %i, status: %s, %i blocks, %i badblocks",this->DbName.c_str(),ret,Status, blcount,badbl);
//	return true;
//	
//  }

#ifdef MAX_RECORDS_IN_MEMORY

std::shared_ptr<DbHandler::DbRecord> DbHandler::get_older() {
    //if(records.empty()) return nullptr;
    auto older = records.begin()->second;
    for(auto &record : records) {
        if(record.second->getLastAccess() < older->getLastAccess())
            older = record.second;
    }
    return older;
}

bool DbHandler::free_older() {
    if(records.size() >= MAX_RECORDS_IN_MEMORY) {
        auto older = get_older();
        records.erase(older->key);
        return true;
    }
    return false;
}

#endif
//------------------------------------------------------------------------------
bool DbHandler::interlocked_insert(const unsigned char *pkey,
                        size_t key_sz,
                        const unsigned char *pdata,
                        size_t data_sz,
                        LoadMode lm,
                        char *Status,
                        size_t StatusSz)
{
    DB_LOCK
    return insert(pkey, key_sz, pdata, data_sz, lm, Status, StatusSz);
}

bool DbHandler::interlocked_obtain(const unsigned char *pkey,
                        size_t key_sz,
                        unsigned char *&data,
                        size_t &data_sz,
                        LoadMode lm,
                        char *Status,
                        size_t StatusSz)
{
    DB_LOCK
    return obtain(pkey, key_sz, data, data_sz, lm, Status, StatusSz);
}

bool DbHandler::interlocked_del(const unsigned char *pkey,
                     size_t key_sz,
                     char *Status,
                     size_t StatusSz)
{
    DB_LOCK
    return del(pkey, key_sz, Status, StatusSz);
}

std::list<std::string> DbHandler::interlocked_enumerate(unsigned char *pkey,
                                             size_t key_sz,
                                             LoadMode lm,
                                             size_t offset,
                                             size_t limit,
                                             char *Status,
                                             size_t StatusSz)
{
    DB_LOCK
    return enumerate(pkey,
            key_sz,
            lm,
            offset,
            limit,
            Status,
            StatusSz);
}

std::list<key_type> DbHandler::interlocked_enum_keys(unsigned char *pkey,
                                          size_t key_sz,
                                          LoadMode lm,
                                          size_t offset,
                                          size_t limit,
                                          char *Status,
                                          size_t StatusSz)
{
    DB_LOCK
    return enum_keys(pkey,
                            key_sz,
                            lm,
                            offset,
                            limit,
                            Status,
                            StatusSz);
}

size_t DbHandler::interlocked_enum_del(unsigned char *pkey,
                            size_t key_sz,
                            char *Status,
                            size_t StatusSz)
{
    DB_LOCK
    return enum_del(pkey,
                           key_sz,
                           Status,
                           StatusSz);
}
//------------------------------------------------------------------------------
bool DbHandler::DbRecord::setPath(std::string &rec_path) {
    auto c_key_fname = extract_key_fname(rec_path.c_str());
    if(c_key_fname) {
		if (key.from_hex(c_key_fname)) {
			path = rec_path;
			return true;
		}
	}
    return false;
}

const std::string &DbHandler::DbRecord::getPath() {
    return path;
}

bool DbHandler::DbRecord::load(LoadMode _lm) {
    switch(_lm)
    {
        case lmMap:
        {
#ifdef _WIN32
			fd = CreateFileA(path.c_str(), 
				GENERIC_READ, 
				FILE_SHARE_READ | FILE_SHARE_WRITE, 
				nullptr, 
				OPEN_EXISTING, 
				FILE_ATTRIBUTE_NORMAL, 
				nullptr);
			if (fd == INVALID_HANDLE_VALUE) {
				logger.err("CreateFileA: 0x%08X", GetLastError());
				lm = lmInvalid;
				Data = nullptr;
				DataSz = 0;
				return false;
			}
			else {
				logger.dbg("CreateFileA: %s file opened successfully", path.c_str());
			}
			DWORD szHigh;
			DWORD szLow = GetFileSize(fd, &szHigh);
			const size_t c_sz = szLow + (szHigh << 0x20);
			logger.dbg("GetFileSize: %s file size %lu", path.c_str(), c_sz);
			hMap = CreateFileMapping(fd,
				NULL,
				PAGE_READONLY,
				szHigh,
				szLow,
				NULL);
			if (!hMap) {
				logger.err("CreateFileMapping: 0x%08X", GetLastError());
				CloseHandle(fd);
				lm = lmInvalid;
				fd = INVALID_HANDLE_VALUE;
				Data = nullptr;
				DataSz = 0;
				return false;
			}
			Data = (unsigned char *)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, c_sz);
			if (!Data) {
				logger.err("MapViewOfFile: 0x%08X", GetLastError());
				CloseHandle(hMap);
				hMap = nullptr;
				CloseHandle(fd);
				lm = lmInvalid;
				fd = INVALID_HANDLE_VALUE;
				Data = nullptr;
				DataSz = 0;
				return false;
			}
			DataSz = c_sz;

#else
            fd = open(path.c_str(), O_RDONLY, 0);
            if(fd < 0) {
                lm = lmInvalid;
                fd = -1;
                Data = nullptr;
                DataSz = 0;
                return false;
            }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
            struct stat st;
            ZEROIZE(&st);
#pragma GCC diagnostic pop
            if(fstat(fd, &st) < 0) {
                //
                lm = lmInvalid;
                fd = -1;
                close(fd);
                Data = nullptr;
                DataSz = 0;
                return false;
            }
            if(st.st_size < sizeof(key_type)) {
                lm = lmInvalid;
                fd = -1;
                close(fd);
                Data = nullptr;
                DataSz = 0;
                return false;
            }
            Data = (unsigned char *)mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_SHARED, fd, 0);
            if(Data == MAP_FAILED) {
                //
                lm = lmInvalid;
                fd = -1;
                close(fd);
                Data = nullptr;
                DataSz = 0;
                return false;
            }
            DataSz = (size_t)st.st_size;
#endif
            lm = lmMap;
            return true;
        }
        case lmLoad:
            Data = loadBufferFromFile(path.c_str(), DataSz);
            if(!Data) {
                DataSz = 0;
                lm = lmInvalid;
                return false;
            }
            if(DataSz < sizeof(key_type)) {
                delete[] Data;
                Data = nullptr;
                DataSz = 0;
                lm = lmInvalid;
                return false;
            }
            lm = lmLoad;
            return true;
        case lmEmpty:
            lm = _lm;
            Data = nullptr;
            DataSz = 0;
            return true;
        default:
            lm = lmInvalid;
            return false;
    }
}

bool DbHandler::DbRecord::unload() {
    switch(lm)
    {
        case lmMap:
        {
#ifdef _WIN32
			if (!Data) {
				return false;
			}
			if (!DataSz) {
				return false;
			}
			if (fd == INVALID_HANDLE_VALUE) {
				return false;
			}
			if (!hMap) {
				CloseHandle(fd);
				return false;
			}
			if (UnmapViewOfFile(Data)) {
				logger.dbg("UnmapViewOfFile: unmapped successfully");
			}
			else {
				logger.err("UnmapViewOfFile: error 0x%08X", GetLastError());
			}
			if (CloseHandle(hMap)) {
				logger.dbg("CloseHandle: map closed successfully");
			}
			else {
				logger.err("CloseHandle: map close error 0x%08X", GetLastError());
			}
			if (CloseHandle(fd)) {
				logger.dbg("CloseHandle: file closed successfully");
			}
			else {
				logger.err("CloseHandle: file close error 0x%08X", GetLastError());
			}
#else
            if(!Data) {
                return false;
            }
            if(!DataSz) {
                return false;
            }
            if(fd < 0) {
                return false;
            }
            munmap(Data, DataSz);
            close(fd);
            Data = nullptr;
            DataSz = 0;
            fd = -1;
#endif
            lm = lmEmpty;
            return true;
        }
        case lmLoad:
        {
            if(Data) {
                delete[] Data;
                Data = nullptr;
            }
            lm = lmEmpty;
            DataSz = 0;
            return true;
        }
        case lmEmpty:
            lm = lmEmpty;
            Data = nullptr;
            DataSz = 0;
            return true;
        default:
            lm = lmInvalid;
            return false;
    }
}
void DbHandler::state_own_lasthash(unsigned char * new_lhash) {
	/// вызывать из init (любого) устанавливать own_last_hash== [.EXT/last] или 0x00000;
	std::string fullpt = DbPath + std::string("/.EXT/last");
	if (new_lhash == nullptr) {		
		if (fileExists(fullpt.c_str())) {
			//hash_type * ptr_last_hash = &(own_last_hash);
			size_t i = 0;
			//ptr_last_hash = (hash_type *)loadBufferFromFile(fullpt.c_str(), i, nullptr, 0); // , sizeof(hash_type));
			memcpy((unsigned char *)&own_last_hash.data, loadBufferFromFile(fullpt.c_str(), i, nullptr, 0), hash_type::get_sz());
		}
		else {
			own_last_hash = hash_type();
		}
	}
	else {
		/*hash_type * plast_hash = &own_last_hash;
		plast_hash = (hash_type *)new_lhash;*/
		own_last_hash = *((hash_type *)new_lhash);
		saveBufferToFile(fullpt.c_str(), (const unsigned char *)new_lhash, hash_type::get_sz(), nullptr);
	}

}

void DbHandler::save_balances_sql() {
	int rc = 0;
	int err_count = 0;
	sqlite3_stmt* stmt = nullptr;
	char keybuff[100] = { '\0' };
	rc = sqlite3_exec(sql_handler, "BEGIN;", nullptr, nullptr, nullptr);
	if (rc) {
		logger.err("save_balances_sql FAILED, error %d: %s", rc, sqlite3_errmsg(sql_handler));
		return;
	}
	for (auto itm : balances) {		
		rc = sqlite3_prepare_v2(sql_handler, SQL_BALANCE_INSERT, sizeof(SQL_BALANCE_INSERT), &stmt, nullptr);
		if (rc == SQLITE_OK) {
			//sqlite3_bind_blob(stmt, 1, itm.first.data, public_type::get_sz(), SQLITE_STATIC);
			itm.first.to_hex(keybuff, 100, public_type::get_sz());
			sqlite3_bind_text(stmt, 1, keybuff, -1, SQLITE_STATIC);
			sqlite3_bind_int(stmt, 2, itm.second.incoming.high);
			sqlite3_bind_int64(stmt, 3, itm.second.incoming.low);
			sqlite3_bind_int(stmt, 4, itm.second.outgoing.high);
			sqlite3_bind_int64(stmt, 5, itm.second.outgoing.low);
			sqlite3_bind_blob(stmt, 6, own_last_hash.data, hash_type::get_sz(), SQLITE_STATIC);
			err_count += (sqlite3_step(stmt) != SQLITE_DONE);
		}
		else
			err_count++;
	}
	sqlite3_finalize(stmt);
	rc = sqlite3_exec(sql_handler, "COMMIT;", nullptr, nullptr, nullptr);
	if (rc) {
		logger.err("save_balances_sql FAILED, error %d: %s", rc, sqlite3_errmsg(sql_handler));
		return;
	}
	if (err_count == 0)
		logger.dbg("balance cash saved successfully");
	else
		logger.dbg("balance cash saved width %i errors!", err_count);

}

void DbHandler::load_balances_sql() {
	int rc = 0;
	int rec_counter = 0;
	sqlite3_stmt* stmt = nullptr;
	rc = sqlite3_prepare_v2(sql_handler, SQL_BALANCE_GET, -1, &stmt, nullptr);
	if (rc == SQLITE_OK) {
		rc = sqlite3_step(stmt);
		while (rc == SQLITE_ROW) {
			auto pubchr = (char *)sqlite3_column_text(stmt, 0);
			public_type pub;
			pub.from_hex(pubchr);
			iobalance_t iob = iobalance_t();
			iob.incoming.high = (uint32_t)sqlite3_column_int(stmt, 1);
			iob.incoming.low = (uint64_t)sqlite3_column_int64(stmt, 2);
			iob.outgoing.high = (uint32_t)sqlite3_column_int(stmt, 3);
			iob.outgoing.low = (uint64_t)sqlite3_column_int64(stmt, 4);
			std::pair<public_type ,iobalance_t> b_itm = std::make_pair(pub, iob);
			balances.emplace(b_itm);
			rc = sqlite3_step(stmt);
			rec_counter++;
		}
		sqlite3_finalize(stmt);
	}
	logger.dbg("LOAD BALANCES: loaded %i records, in 'map::balances' %i unique records", rec_counter, balances.size());

}
int DbHandler::save_balance_any(public_type *pkey, iobalance_t * balance) {
	int rc = 0;
	sqlite3_stmt* stmt = nullptr;
	char keybuff[100] = { '\0' };
	rc = sqlite3_prepare_v2(sql_handler, SQL_BALANCE_INSERT, sizeof(SQL_BALANCE_INSERT), &stmt, nullptr);
	if (rc == SQLITE_OK) {
		//sqlite3_bind_blob(stmt, 1, &pkey, public_type::get_sz(), SQLITE_STATIC);
		pkey->to_hex(keybuff, 100, public_type::get_sz());
		sqlite3_bind_text(stmt, 1, keybuff, -1, SQLITE_STATIC);
		sqlite3_bind_int(stmt, 2, balance->incoming.high);
		sqlite3_bind_int64(stmt, 3, balance->incoming.low);
		sqlite3_bind_int(stmt, 4, balance->outgoing.high);
		sqlite3_bind_int64(stmt, 5, balance->outgoing.low);
		sqlite3_bind_blob(stmt, 6, own_last_hash.data, hash_type::get_sz(), SQLITE_STATIC);
		rc = (sqlite3_step(stmt) != SQLITE_DONE);
	}
	sqlite3_finalize(stmt);
	return rc;

}

unsigned char *DbHandler::DbRecord::getData() {
#ifdef MAX_RECORDS_IN_MEMORY
    renew();
#endif
    return Data;
}

bool DbHandler::DbRecord::valid() {
    key_type tmp_key;
    const char *c_fname = extract_key_fname(path.c_str());
    if(!c_fname) return false;
    if(strlen(c_fname) != (sizeof(key_type) << 1)) return false;
    if(!tmp_key.from_hex(c_fname)) return false;
    if(memcmp(tmp_key.data, key.data, sizeof(key_type)) != 0) return false;
/*
    char hexBuffer[0x100];
    if(!DbHandler::key2hex(tmp_key, hexBuffer, COUNT(hexBuffer))) return false;
#ifdef WIN32
    if(strcmpi(c_fname, hexBuffer) != 0) return false;
#else
    if(strcasecmp(c_fname, hexBuffer) != 0) return false;
#endif
*/
    switch(lm)
    {
        case lmInvalid: return false;
        case lmMap:
        case lmLoad:
            return true;//TODO: check for signature
        case lmEmpty:
            return (!Data) && (!DataSz);
        default:
            return false;
    }
}

DbHandler::DbRecord::DbRecord() :
#ifdef _WIN32
	fd(INVALID_HANDLE_VALUE),
	hMap(nullptr)
#else
	fd(-1)
#endif
                                              , lm(lmEmpty)
                                              , path("")
                                              , Data(nullptr)
                                              , DataSz(0)
#ifdef MAX_RECORDS_IN_MEMORY
                                              , last_access(high_resolution_clock::now())
#endif
{}

DbHandler::DbRecord::DbRecord(std::string &rec_path, LoadMode _lm) :
#ifdef _WIN32
	fd(INVALID_HANDLE_VALUE),
	hMap(nullptr),
#else
	fd(-1),
#endif
                                                                            lm(lmEmpty),
                                                                            path(""),
                                                                            Data(nullptr),
                                                                            DataSz(0)
{
    ZEROARR(key.data);
    setPath(rec_path) && load(_lm);
}
/// отсюда --Ra_SYNC_HANDLER definition
//
//bool operator<(const SyncItem &itm1, const SyncItem &itm2) {
//	return itm1.need_hash < itm2.need_hash;
//}
//
//bool SyncHandler::init_handler() {
//	this->senders = new SyncSenders();
//	this->SyncQueue = new SyncQueueType();	
//	return true;
//}
//bool SyncHandler::append(hash_type *needhash, sockaddr_in * sender) {
//	mtx.lock();
//	if (i_SyncState == eSyncNotLanch)
//		init_handler();
//	Sync_sender_item s = Sync_sender_item(sender);
//	unsigned long long key = s.calc_sender_key();
//
//	senders->emplace(std::make_pair(key, s));
//	SyncItem r = SyncItem(needhash, key);
//	SyncQueue->emplace(std::make_pair(r.need_hash, r));
//	mtx.unlock();
//	return true;
//};
//bool SyncHandler::set_GetEntitySended(hash_type *key_hash) {
//	mtx.lock();
//	bool rslt = false;
//	auto  itm = SyncQueue->at(&key_hash);
//	if (itm != SyncQueue->end()) {
//		itm->beenGetEntity = true;
//		rslt = true;
//	}
//	mtx.unlock();
//	return rslt;
//};
//bool set_EntityReceived(hash_type *key_hash);
//bool GetNextResponce(hash_type *hash_buffer, sockaddr_in *addr_buffer);
//bool checkQueue();

bool DbHandler::dropLastHash(char *Status, const size_t StatusSz) {
    SILENCE
    DB_INITIALIZED

    const std::string c_last_path = DbPath + std::string("/.EXT/last");
    return saveBufferToFile(c_last_path.c_str(),
            own_last_hash.data,
            hash_type::get_sz(),
            Status,
            StatusSz);
}



bool DbHandler::dropBlock(char *Status, const size_t StatusSz) {
    SILENCE
    DB_INITIALIZED

    DB_LOCK

    auto t = std::chrono::high_resolution_clock::now();

    if(block_meta.block_ptr) {
        // TODO: записывать пустой блок за увеличенное время (больше 200мс) при отсутствии активности
        if(block_meta.getMemSize() <= 77) return false; //< игнорируем маленькие блоки
		block_meta.close_block();
		auto temp_last_hash = block_meta.getHash();
        bool result =  insert(temp_last_hash.data,
                        hash_type::get_sz(),
						block_meta.block_ptr.get()->getBlob(),
						block_meta.getMemSize(),
                        lmLoad,
                        Status,
                        StatusSz);
        if (result) {
			own_last_hash = temp_last_hash;
			dropLastHash(Status, StatusSz);
		}
        index(block_meta.block_ptr.get()->getBlob(), block_meta.getMemSize()); //< TODO: вынести в параллельный поток
		block_meta.clear_buffer(own_last_hash);
        //block_ptr = BLOCK_TYPE::create(own_last_hash);
        return result;
    } else {
        auto int_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(t.time_since_epoch()).count();
        logger.dtl("%llu: There is no block to drop", int_ns / 1000000);
        return false;
    }
}

bool DbHandler::appendTransaction(Transaction &transaction, char *Status, const size_t StatusSz) {
	if(transaction.sender_public == transaction.receiver_public) {
		if (counter.blocks_counter > 0) {
			return false;
		}
	}

	if(get_balance(transaction.sender_public) < transaction.amount) {
		if (counter.blocks_counter) {
			return false;
		}
	}

    SILENCE
    DB_INITIALIZED

    DB_LOCK

    if(!block_meta.block_ptr) {
		block_meta = BLOCK_TYPE::create(own_last_hash);
	}
    //return block_meta.append_transaction(transaction);
	return block_meta.append_data((unsigned char*)&transaction, btTransaction);

}

bool DbHandler::appendBinaryData(unsigned char *append_data, unsigned int appdata_sz, char *Status , size_t StatusSz ){
	SILENCE
		DB_INITIALIZED

		DB_LOCK

		if (!block_meta.block_ptr) {
			block_meta = BLOCK_TYPE::create(own_last_hash);
		}
	
	return block_meta.append_data(append_data, btBinaryData,appdata_sz);
}
bool DbHandler::insert_host(const char *ip, const unsigned short &port, const public_type &pub) {
    sqlite3_stmt* stmt = nullptr;
    int rc = 0;

    rc = sqlite3_prepare_v2(sql_handler,SQL_HOST_INSERT,-1,&stmt, nullptr);

    if (rc != SQLITE_OK){
        fprintf(stderr,"cannot prepare_v2\n");
        return false;
    }
    // Если определен публичный ключ при вставке, то используем его, иначе используем свой собственный
    sqlite3_bind_blob(stmt, 1, pub.data, 32, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, ip, -1, SQLITE_STATIC);
    sqlite3_bind_int(stmt, 3, port);

    rc = sqlite3_step(stmt);
    if (rc != SQLITE_DONE){
        printf("ERROR inserting data: %s\n", sqlite3_errmsg(sql_handler));
    }
    sqlite3_finalize(stmt);

    sockaddr_in ip_addr{};
    ip_addr.sin_family = AF_INET;
    ip_addr.sin_port = htons(port);
    ip_addr.sin_addr.s_addr = inet_addr(ip);
    hosts.appendHost(public_key, ip_addr, ADDR_TYPE::atUnknown);

    return true;
}

bool DbHandler::update_hosts() {
	// old:
	//hosts.clear();
	sqlite3_stmt* stmt = nullptr;
	int rc = 0;
	rc = sqlite3_prepare_v2(sql_handler, SQL_HOST_SELECT, -1, &stmt, nullptr);
	if (rc != SQLITE_OK) {
		fprintf(stderr, "cannot prepare_v2\n");
		return false;
	}
	rc = sqlite3_step(stmt);
	//char buffer[64];
	while(rc == SQLITE_ROW) {
		//unsigned char p[64];
		auto pub = (unsigned char*)sqlite3_column_text(stmt, 0);
		auto addr = (const char*)sqlite3_column_text(stmt, 1);
		unsigned short port = sqlite3_column_int(stmt, 2);
		public_type key;
		memcpy(key.data, pub, sizeof(public_type));
		sockaddr_in ip_addr{};
		ip_addr.sin_family = AF_INET;
		ip_addr.sin_port = htons(port);
		ip_addr.sin_addr.s_addr = inet_addr(addr);
		hosts.appendHost(key, ip_addr, ADDR_TYPE::atUnknown);
		rc = sqlite3_step(stmt);
	}
	return true;
}

Amount DbHandler::get_balance(const public_type &key) {
	auto b = balances.find(key);
	if (b == balances.end()) return Amount{};
	try
	{
		return b->second.incoming - b->second.outgoing;
	}
	catch (const std::out_of_range& e)
	{
		logger.err("get_balance:%s", e.what());
		return Amount{};
	}
}

bool DbHandler::have_transactions(const public_type &key) {
	return balances.find(key) != balances.end();
}

//------------------------------------------------------------------------------
