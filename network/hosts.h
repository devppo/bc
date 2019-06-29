#pragma once

#ifdef _WIN32

#include <winsock2.h>

#else

#include <sys/socket.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/unistd.h>

#endif

#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <map>
#include <memory>
#include <mutex>

#include <common/defs.h>
#include <common/macro.h>

#include "crypto.h"
#include <common/log.h>



bool operator<(const sockaddr_in &addr0, const sockaddr_in &addr1);
bool operator>(const sockaddr_in &addr0, const sockaddr_in &addr1);
bool operator==(const sockaddr_in &addr0, const sockaddr_in &addr1);

enum ADDR_TYPE : int32_t {
	atOffline = -2, //< узел признаётся вне сети
	atUnknown = -1,
	atDynamicIP = 0,
	atStaticIP,
	atSymNAT,
	atConeNAT,
	atAddrRestrictedNAT,
	atPortRestrictedNAT,
	atIPv6,
	atURL,

	atCount
};
typedef struct Host {
	Host(const sockaddr_in &addr, const ADDR_TYPE a_type) : address(addr), addr_type(a_type) {}
    sockaddr_in address;
	ADDR_TYPE addr_type;
} *HHosts, *PHosts;

bool operator<(const Host &h1, const Host &h2);


typedef struct Hosts {
    appendResult appendHost(const public_type &pubkey, const sockaddr_in &addr, const ADDR_TYPE &addr_type);
    size_t getHostsCount();
    bool getHost(size_t index, sockaddr_in &addr, public_type &pubkey, ADDR_TYPE &addr_type);
	bool getHost(public_type &pubkey, const sockaddr_in &addr, const ADDR_TYPE &addr_type);
    bool removeHost(const sockaddr_in &addr, const ADDR_TYPE &addr_type);
	bool getMainHost(public_type &pubkey,  sockaddr_in &addr,  ADDR_TYPE &addr_type);
	bool getMainHost(sockaddr_in &addr);
	bool getMainHost();
	bool setMainHost(sockaddr_in addr);
    void clear();
private:
	std::map<Host, public_type> hosts;
	std::mutex m;
	PHosts mainHost = nullptr;
} *HHOSTS, *PHOSTS;

extern Hosts hosts;

