#pragma once

#include <common/defs.h>

#include <deque>
#include <memory>
#include <mutex>
#include <thread>
#include <atomic>
#include <map>

#include <common/macro.h>
#include <blake2.h>

#ifdef _WIN32
/* See http://stackoverflow.com/questions/12765743/getaddrinfo-on-win32 */
  #ifndef _WIN32_WINNT
    #define _WIN32_WINNT 0x0501  /* Windows XP. */
  #endif
#include <WinSock2.h>
#include <Windows.h>
#include <WS2tcpip.h>
#else
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/time.h>
/* Assume that any non-Windows platform uses POSIX-style sockets instead. */
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>  /* Needed for getaddrinfo() and freeaddrinfo() */
#include <unistd.h> /* Needed for close() */
#endif

#include "proto.h"
#include "common/log.h"
#include "hosts.h"
#include "common/types.h"
//extern struct event_base * buf_timers_base;
bool net_sendto(char *host, unsigned short port,
				unsigned char *Data, size_t DataSz, ENTITY_DATA_TYPE dt = edtBlock,
				char *Status = nullptr, size_t StatusSz = 0);
bool net_recv(unsigned char *Buffer,
			  size_t &BufferSz, ENTITY_DATA_TYPE &edata_type,
			  char *Status = nullptr, size_t StatusSz = 0);

bool net_launch(const public_type &ownPub,
				const private_type &ownPriv,
				const char *host = nullptr, unsigned short port = UDP_PORT);
void net_stop();
bool net_available();

bool net_command_iam(const char *host, unsigned short port,
					 char *Status = nullptr, size_t StatusSz = 0);
bool net_command_iamtoo(const char *host, unsigned short potr,
						char *Status = nullptr, size_t StatusSz = 0);
bool net_command_iamtoo(sockaddr_in addr, char *Status = nullptr, size_t StatusSz = 0);
bool net_command_heis(const char *host, unsigned short port,
					  public_type &his_pub,
					  const char *his_host,
					  unsigned short his_port,
					  char *Status = nullptr, size_t StatusSz = 0);
bool net_command_get_entity(const char *host, unsigned short port, hash_type &entity_hash,
							char *Status = nullptr, size_t StatusSz = 0);

bool net_command_lasthash(const char *host, unsigned short port, char *Status = nullptr, size_t StatusSz = 0);
bool net_command_lasthash(sockaddr_in addr, char *Status = nullptr, size_t StatusSz = 0);
bool net_command_get_entitypart(const char *host, unsigned short port, hash_type &entity_hash, uint16_t offset,
								uint16_t parts_count = 1,
								char *Status = nullptr, size_t StatusSz = 0);
bool net_command_get_entitypart(sockaddr_in addr, hash_type &entity_hash, uint16_t offset, uint16_t parts_count = 1,
								char *Status = nullptr, size_t StatusSz = 0);
bool net_present_me();

sockaddr_in get_self_sin();

int net_synclasthash();
int net_sync_proc();
bool net_command_getroundinfo(const char *host, unsigned short port);
bool net_command_getroundinfo(sockaddr_in addr);
bool net_command_sendroundinfo(const char *host, unsigned short port);
bool net_command_sendroundinfo(sockaddr_in addr);
bool net_command_get_restorechain(const char *host, unsigned short port, hash_type &last_hash, int part = -1);
bool net_command_get_restorechain(sockaddr_in addr, hash_type &last_hash, int part = -1);
bool net_round_broadcast();
typedef std::map<hash_type, std::shared_ptr<PACKAGE_BUFFER>> PkgBufMap;

//typedef struct {
//	size_t num;
//	hash_type hash;
//}RestorChainItem;
//typedef struct {
//	// структура для передачи цепочки требуемых хешей в ответ на запрос GetRestoreChain
//public:
//	//size_t get_bytesz() { return hash_type::get_sz() + sizeof(sz) + sizeof(sockaddr_in) + (hash_type::get_sz() * sz); }
//	hash_type final_hash{};
//	sockaddr_in sender{};
//	size_t sz = 0;
//	hash_type chain[0];
//} RestoreChainInfo;

//---for buffers complete events
event * add_buftimer(timeval tv,void *arg);
void erase_bad_recv_buffer(hash_type hash_id);

