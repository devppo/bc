#include <chrono>
#include "syncheader.h"
#include "blocks_thread.h"


bool operator<(const SyncItem &itm1, const SyncItem &itm2) {
	return itm1.need_hash < itm2.need_hash;
}

void SyncHandler::init_handler() {
	senders.clear();
	syncqueue.clear();
	t_interval = 0;
	i_SyncState = eSyncLanch;
}

bool SyncHandler::append(hash_type &needhash, sockaddr_in & sender, int n) {
	mtx.lock();
	bool ret = false;
	if (i_SyncState != eSyncLanch )
		init_handler();
	
	Sync_sender_item s(sender);
	if (s.address.sin_family == AF_UNSPEC)
		s.address.sin_family = AF_INET;
	auto it = senders.find(s.sender_key);
	if (it == senders.end())
		senders.insert(std::pair<unsigned long long, Sync_sender_item>(s.sender_key, s));
	bool canInsert = true;
	if (bottom_hash != needhash) {
		SyncItem r(&needhash, s.sender_key);
		for (auto it : syncqueue) {
			if (it.second.need_hash == needhash) {
				if (it.second.beenReceived == false)
					syncqueue.at(it.first).beenGetEntity = false;
				canInsert = false;
				break;
			}
		}
		if (canInsert) {
			if (!db_singleton.hashExists(r.need_hash)) {
				unsigned int nm = n == -1 ? syncqueue.size() : n;
				syncqueue.insert(std::pair<unsigned int, SyncItem>(nm, r));
			}
		}
		
	}
	mtx.unlock();
	return ret;
}

bool SyncHandler::set_GetEntitySended(hash_type &key_hash) {
	mtx.lock();
	bool ret = false;
	for (auto it : syncqueue) {
		if (it.second.need_hash == key_hash) {
			syncqueue.at(it.first).beenGetEntity = true;
			//if (t_interval == 0)
				t_interval = time(nullptr);
			ret = true;
			break;
		}
	}	
	mtx.unlock();
	return ret;
}

bool SyncHandler::set_EntityReceived(hash_type &key_hash) {
	mtx.lock();
	bool ret = false;
	for (auto it : syncqueue) {
		if (it.second.need_hash == key_hash) {
			syncqueue.at(it.first).beenReceived = true;
			if (!syncqueue.at(it.first).beenGetEntity) syncqueue.at(it.first).beenGetEntity = true;
			t_interval = time(nullptr);
			ret = true;
			break;
		}
	}
	mtx.unlock();
	return ret;
}

bool SyncHandler::GetNextResponce(hash_type *hash_buffer, sockaddr_in *addr_buffer) {
	bool ret = false;
	mtx.lock();
	for (auto itr = syncqueue.begin(); itr != syncqueue.end(); itr++) {
		if ((!itr->second.beenGetEntity)) {
			*hash_buffer = itr->second.need_hash;
			if (itr->second.sender_key != 0) {
				sockaddr_in send_addr = senders.at(itr->second.sender_key).address;
				memcpy(addr_buffer, &send_addr, sizeof(sockaddr_in));
			}
			else {
				if (!senders.empty()) {
					auto snd = senders.cbegin();
 					auto anyaddr = (snd)->second.address;
					memcpy(addr_buffer, &anyaddr, sizeof(sockaddr_in));
				}
				else
					addr_buffer->sin_family=AF_UNSPEC;
			}
			ret = true;
			break;
		}
	}
	mtx.unlock();
	return ret;
}

bool SyncHandler::checkQueue() {
	
	mtx.lock();
	bool q_empty = true;
	for (auto itr = syncqueue.begin(); itr != syncqueue.end(); itr++) {
		if (!itr->second.beenGetEntity) {
			q_empty = false;
			break;
		}
		else 
			if (!itr->second.beenReceived) {
				if (db_singleton.hashExists(itr->second.need_hash)) {
					syncqueue.at(itr->first).beenReceived = true;
				}
				else {
					q_empty = false;
					break;
				}
			}
	}
 	if (q_empty) {
		i_SyncState = eSyncComplete;		
 		senders.clear();
		syncqueue.clear();
	}
	else {
		if (difftime(time(nullptr), t_interval) >= SYNC_QUEUE_INTERVAL_SEC) {
			if (!buffcount_over)
			{
				for (auto itr = syncqueue.begin(); itr != syncqueue.end(); itr++) {
					if (itr->second.beenGetEntity && !itr->second.beenReceived)
						syncqueue.at(itr->first).beenGetEntity = false;
				}
			}
			t_interval = time(nullptr);
		}
	}
	mtx.unlock();
	return !syncqueue.empty();
}

