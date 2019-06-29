#pragma once

#include <common/defs.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <memory>
#include <vector>
#include <map>
#include <mutex>
#include <chrono>
#include <thread>

#ifdef _WIN32
#else
#include <sys/dir.h>
#endif

#include <common/macro.h>
#include "common/types.h"
#include "common/log.h"
#include "../network/hosts.h"

#ifdef MAX_RECORDS_IN_MEMORY
#include <chrono>
#endif

#include "common/fshelper.h"
#include "sqlite3.h"
#include "sql_requests.h"

#include "crypto.h"

#include "db_types.h"
#include "block_type.h"
#include "syncheader.h"

#define DB_INITIALIZED      if(!db_initialized) { \
    SPRINTF(Status, "Database is not initialized"); \
    return 0;\
}

//using namespace racrypto;

#ifdef MAX_RECORDS_IN_MEMORY
using namespace std::chrono;
#endif


const char *extract_key_fname(const char *key_path);

typedef enum {
    lmInvalid = -1,

    lmEmpty = 0,
    lmLoad,
    lmMap ,

    lmCount
} LoadMode;


typedef struct DbHandler {
public:
	DbHandler() : sql_handler(nullptr)
		, db_initialized(false)
	{}
	~DbHandler() {
		deinit();
	}
    virtual bool init(const char *db_name,
              const public_type &pub,
              const private_type &priv,
              char *Status = nullptr,
              size_t StatusSz = 0);
    virtual bool init(const char *db_name,
              char *Status = nullptr,
              size_t StatusSz = 0);
    bool deinit(char *Status = nullptr,
                size_t StatusSz = 0);
    bool initialized();
//----------------------------------------------------------------------------------------------------------------------
    bool interlocked_insert(const unsigned char *pkey,
            size_t key_sz,
            const unsigned char *pdata,
            size_t data_sz,
            LoadMode lm = lmLoad,
            char *Status = nullptr,
            size_t StatusSz = 0);
    bool interlocked_obtain(const unsigned char *pkey,
            size_t key_sz,
            unsigned char *&data,
            size_t &data_sz,
            LoadMode lm = lmLoad,
            char *Status = nullptr,
            size_t StatusSz = 0);
    bool interlocked_del(const unsigned char *pkey,
             size_t key_sz,
             char *Status = nullptr,
             size_t StatusSz = 0);
	std::list<std::string> interlocked_enumerate(unsigned char *pkey,
                           size_t key_sz,
                           LoadMode lm = lmEmpty,
                           size_t offset = 0,
                           size_t limit = (~(size_t)0),
                           char *Status = nullptr,
                           size_t StatusSz = 0);
	std::list<key_type> interlocked_enum_keys(unsigned char *pkey,
                           size_t key_sz,
                           LoadMode lm = lmEmpty,
                           size_t offset = 0,
                           size_t limit = (~(size_t)0),
                           char *Status = nullptr,
                           size_t StatusSz = 0);
    size_t interlocked_enum_del(unsigned char *pkey,
                    size_t key_sz,
                    char *Status = nullptr,
                    size_t StatusSz = 0);
	int restore_chain(size_t *chainblcount, size_t *badblcount,  hash_type * curr_lasthash,  hash_type * need_hash, char * Status=nullptr, int StatusSz=0); // восстановление цепочки хешей и запись ее в SQLite
	bool getChainIdHash( hash_type * chainid_hash); //возвращает 0й хеш для идентификации цепочки
	bool appendHash_intochaincashe(hash_type added_hash);
	std::vector<RestoreChainItem> get_chainhashes(hash_type &first);
//----------------------------------------------------------------------------------------------------------------------
	bool index(const unsigned char *block_buffer, size_t block_sz, META_INFO *metainfoptr=nullptr);
	std::string getDbName() { return DbName; }
	std::string getDbPath() { return DbPath; }
    public_type &getDbPublicKey() { return public_key; }
    private_type &getDbPrivateKey() { return private_key; }
    bool full_index();
	bool getNextHashByChain(const hash_type& nhash,  const hash_type *r_hash);
	bool checkIntegrityChain( bool check_valid_hashes=false, bool force_restorechain=false);
	//bool checkIntegrityChainv2(bool check_valid_hashes = false);
	bool hashExists(key_type hash,bool inchain=false);
//--- FOR BASE Syncronization -------------------
	SyncHandler hSync;
	//bool DbSyncStart(key_type *newlasthash, sockaddr_in *syncaddr, char *Status, const size_t StatusSz);	
	//bool DbSyncCheck( char *Status, const size_t StatusSz);
	//bool sync_on = false;
	//sockaddr_in sync_addr;
    bool dropBlock(char *Status = nullptr, size_t StatusSz = 0);
	bool appendTransaction(Transaction &transaction, char *Status = nullptr, size_t StatusSz = 0);
	bool appendBinaryData(unsigned char *append_data, unsigned int appdata_sz, char *Status = nullptr, size_t StatusSz = 0);
    bool insert_host(const char* ip, const unsigned short& port, const public_type& pub);
    bool update_hosts();
	hash_type GetLastHash() { return own_last_hash; }
	
	/*static bool getDbRecordPath(key_type key,
		size_t key_sz,
		const std::string &db_name,
		std::string &fullRecordPath,
		char *Status = nullptr,
		size_t StatusSz = 0)*/;
	Amount get_balance() { return get_balance(public_key); }
	Amount get_balance(const public_type &key);
	bool have_transactions(const public_type &key);
	Counter get_counter() { return counter; }
	void state_own_lasthash(unsigned char * new_lhash = nullptr);
	public_type get_issuer_key() { return issuer_key; }
	
private:
	std::string DbPath;
	std::string DbName;
    public_type public_key;
    private_type private_key;
	sqlite3 *sql_handler;
	bool db_initialized;

	struct iobalance_t {
		Amount incoming;
		Amount outgoing;
	};
	// indexed values
	std::map<public_type, iobalance_t> balances; //< TODO: ввести определение валюты
	// сохранение и загрузка map::balances в sqlite
	void save_balances_sql();
	void load_balances_sql();
	int save_balance_any(public_type *pkey, iobalance_t * balance);
	//std::map<public_type, Amount> balances_income;
	//std::map<public_type, Amount> balances_outgoing;
	Counter counter;

	public_type issuer_key; //< ключ кошелька эмитента
	//BLOCK_PTR block_ptr;
	BLOCK_META block_meta;
	hash_type own_last_hash;
	std::mutex blocks_m;
//----------------------------------------------------------------------------------------------------------------------
    typedef struct DB_LOCKER {
        DbHandler &own_db;
        DB_LOCKER(DbHandler &db) : own_db(db) {
            own_db.blocks_m.lock();
        }
        ~DB_LOCKER() {
            own_db.blocks_m.unlock();
        }
    } *HDB_LOCKER, *PDB_LOCKER;
//----------------------------------------------------------------------------------------------------------------------
	bool insert(const unsigned char *pkey,
				size_t key_sz,
				const unsigned char *pdata,
				size_t data_sz,
				LoadMode lm = lmMap,
				char *Status = nullptr,
				size_t StatusSz = 0);
	bool obtain(const unsigned char *pkey,
				size_t key_sz,
				unsigned char *&data,
				size_t &data_sz,
				LoadMode lm = lmLoad,
				char *Status = nullptr,
				size_t StatusSz = 0);
	bool del(const unsigned char *pkey,
			 size_t key_sz,
			 char *Status = nullptr,
			 size_t StatusSz = 0);
	std::list<std::string> enumerate(unsigned char *pkey,
									 size_t key_sz,
									 LoadMode lm = lmEmpty,
									 size_t offset = 0,
									 size_t limit = (~(size_t)0),
									 char *Status = nullptr,
									 size_t StatusSz = 0);
	std::list<key_type> enum_keys(unsigned char *pkey,
								  size_t key_sz,
								  LoadMode lm = lmEmpty,
								  size_t offset = 0,
								  size_t limit = (~(size_t)0),
								  char *Status = nullptr,
								  size_t StatusSz = 0);
	size_t enum_del(unsigned char *pkey,
					size_t key_sz,
					char *Status = nullptr,
					size_t StatusSz = 0);
	
//----------------------------------------------------------------------------------------------------------------------
	bool dropLastHash(char *Status = nullptr, size_t StatusSz = 0);
	typedef struct DbRecord {
    public:
        DbRecord();
        explicit DbRecord(std::string &rec_path, LoadMode _lm = lmEmpty);
        ~DbRecord() { unload(); }
        key_type key;
        bool setPath(std::string &rec_path);
        const std::string &getPath();
        bool load(LoadMode _lm);
        bool unload();
        bool valid();
        unsigned char *getData();
        size_t getDataSz() { return DataSz; }

#ifdef MAX_RECORDS_IN_MEMORY
        high_resolution_clock::time_point getLastAccess() { return last_access; }
#endif
    private:
#ifdef _WIN32
		void *fd;
		void *hMap;
#else
        int fd;
#endif
        LoadMode lm;
		std::string path;
        unsigned char *Data;
        size_t DataSz;
#ifdef MAX_RECORDS_IN_MEMORY
        high_resolution_clock::time_point last_access;
        void renew() { last_access = high_resolution_clock::now(); }
#endif
    } *HDB_RECORD, *PDB_RECORD;
	std::map<const key_type, std::shared_ptr<DbRecord>> records;
    static bool initDbDirectory(const std::string &db_name,
		std::string &fullDbPath,
                                char *Status = nullptr,
                                size_t StatusSz = 0);
    
	static bool getDbRecordPath(key_type key,
		size_t key_sz,
		const std::string &db_name,
		std::string &fullRecordPath,
		char *Status = nullptr,
		size_t StatusSz = 0);
	static bool getDbRecordPattern(key_type key,
                                   size_t key_sz,
		std::string &Pattern,
                                   char *Status = nullptr,
                                   size_t StatusSz = 0);
    bool setKeys(const public_type &pub_key,
                 const private_type &priv_key);
    bool setSql();
    bool loadKeys(char *Status = nullptr,
                  size_t StatusSz = 0);
    std::shared_ptr<DbRecord> get_loaded(const key_type &key);
    bool unload(const key_type &key);
#ifdef MAX_RECORDS_IN_MEMORY
    std::shared_ptr<DbRecord> get_older();
    bool free_older();
#endif
} *PRA_DB_HANDLER, *HRA_DB_HANDLER;

#define DB_LOCK     DB_LOCKER l(*this);

