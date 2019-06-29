#pragma once
#ifdef _WIN32

#include <winsock2.h>

#else

#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/unistd.h>

#endif

#include <common/defs.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <memory>
#include <map>
#include <mutex>
#include <chrono>

#include "crypto.h"
#include "../network/hosts.h"

#define SYNC_QUEUE_INTERVAL_SEC 60

typedef struct SyncItem {
	SyncItem(hash_type *hash, unsigned long long s_key) : need_hash(*hash), sender_key(s_key) { }
	hash_type need_hash;
	unsigned long long sender_key;
	bool beenGetEntity = false;
	bool beenReceived = false;
} *HSyncItem;

bool operator<(const SyncItem &itm1, const SyncItem &itm2);

typedef struct Sync_sender_item: Host {
	Sync_sender_item(const sockaddr_in &addr /*,const ADDR_TYPE a_type*/) : Host (  addr,ADDR_TYPE::atUnknown) {sender_key= this->address.sin_addr.s_addr + (this->address.sin_port * 100000000000);
	};
	unsigned long long sender_key;	
} *HSyncSenderItem;

typedef struct SyncHandler {
public:
	enum SyncStateEnum {
		eSyncNotLanch,
		eSyncLanch,
		eSyncComplete
	};
	bool buffcount_over = false;
	hash_type top_hash; 
	hash_type bottom_hash;
	sockaddr_in chainsender;
	bool append(hash_type &needhash, sockaddr_in & sender, int n=-1);
	bool set_GetEntitySended(hash_type &key_hash);
	bool set_EntityReceived(hash_type &key_hash);
	bool GetNextResponce(hash_type *hash_buffer, sockaddr_in *addr_buffer);
	bool checkQueue();
	//hash_type GetLastReceived();
	void ClearSyncFlg() { if (i_SyncState == eSyncComplete) i_SyncState = eSyncNotLanch; }
	
	SyncStateEnum SyncState() { return i_SyncState; }
private:
	SyncStateEnum i_SyncState = eSyncNotLanch;
	std::map<unsigned int, SyncItem> syncqueue;
	//std::map<hash_type, SyncItem> ::iterator itr;
	std::map<unsigned long long, Sync_sender_item>  senders ;
	std::mutex mtx;
	time_t t_interval=0;
	void init_handler();
} *HSYNC_HANDLER;

typedef struct {
	size_t num;
	hash_type hash;
}RestoreChainItem;
typedef struct {
	// структура для передачи цепочки требуемых хешей в ответ на запрос GetRestoreChain
public:
	sockaddr_in sender{};
	size_t part_num = 0;
	size_t sz = 0;
	size_t total_sz = 0;
	size_t total_parts = 0;
	hash_type final_hash{};
	RestoreChainItem chain[0];
} RestoreChainInfo;

