#include "blocks_thread.h"
#include "../network/net.h"

//------------------------------------------------------------------------------
DbSingletone db_singleton;
//------------------------------------------------------------------------------
void DbSingletone::blocks_thread_proc() {
    logger.log("Blocks thread started");
    do {
        std::this_thread::sleep_for(std::chrono::milliseconds(BLOCKS_TIMER_MS));
          if (db_singleton.dropBlock()) {
			  db_singleton.appendHash_intochaincashe(db_singleton.GetLastHash());
			auto host_count = hosts.getHostsCount();
        	for(size_t i = 0; i < host_count; ++i) {
        		sockaddr_in cur_addr{};
        		ZEROIZE(&cur_addr);
        		ADDR_TYPE addr_type = atUnknown;
        		public_type pub;
        		if(hosts.getHost(i, cur_addr, pub, addr_type)) {
					net_command_lasthash(inet_ntoa(cur_addr.sin_addr), ntohs(cur_addr.sin_port));
				}
			}
        }
    } while(db_singleton.on_service);
    logger.log("Blocks thread stopped");
}

bool DbSingletone::init(const char *db_name,
						char *Status,
						size_t StatusSz) {
    return DbHandler::init(db_name, Status, StatusSz) && blocks_launch();
}

bool DbSingletone::init(const char *db_name,
						const public_type &pub,
						const private_type &priv,
						char *Status,
						size_t StatusSz) {
    return DbHandler::init(db_name, pub, priv, Status, StatusSz) && blocks_launch();
}

bool DbSingletone::blocks_launch() {
    if(!on_service) {
        blocks_thread = new std::thread(blocks_thread_proc);
        blocks_thread->detach();
        on_service = !blocks_thread->joinable();
        if(on_service) {
            logger.log("Blocks thread launched");
        }
        else {
            logger.err("Blocks threda hasn't been launched");
        }
    }
    return on_service;
}

bool DbSingletone::blocks_stop() {
    on_service = false;
    return !on_service;
}
