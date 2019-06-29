#include "hosts.h"

Hosts hosts;
bool operator<(const sockaddr_in &addr0, const sockaddr_in &addr1) {
    if(htonl(addr0.sin_addr.s_addr) < htonl(addr1.sin_addr.s_addr)) return true;
    if(addr0.sin_port < addr1.sin_port) return true;
    return false;
}

bool operator>(const sockaddr_in &addr0, const sockaddr_in &addr1) {
    if(htonl(addr0.sin_addr.s_addr) > htonl(addr1.sin_addr.s_addr)) return true;
    if(addr0.sin_port > addr1.sin_port) return true;
    return false;
}

bool operator==(const sockaddr_in &addr0, const sockaddr_in &addr1) {
    return addr0.sin_addr.s_addr ==
        addr1.sin_addr.s_addr &&
        addr0.sin_port ==
        addr1.sin_port;
}

bool operator<(const Host &h1, const Host &h2) {
	//return h1.address < h2.address;
	if (h1.address.sin_addr.s_addr == h2.address.sin_addr.s_addr)
		return h1.address.sin_port < h2.address.sin_port;
	else
		return (h1.address.sin_addr.s_addr < h2.address.sin_addr.s_addr);
	//return (h1.address.sin_addr.S_un.S_addr < h2.address.sin_addr.S_un.S_addr) && (h1.address.sin_port<h2.address.sin_port);
}


appendResult Hosts::appendHost(const public_type &pubkey, const sockaddr_in &addr, const ADDR_TYPE &addr_type) {
    appendResult ar = arUndefined;
    m.lock();
    Host host(addr, addr_type);
	if (hosts.count(host) != 0) {
		ar = arAlreadyExists;
		//TODO - обновить ключ
	}
	else {
		hosts.insert(std::pair<Host, public_type>(host, pubkey));
		ar = arAppended;
	}
    //auto it = hosts.find(host);
    //if(it != hosts.end()) {
    //    ar = arAlreadyExists;
    //    it->second = pubkey; //< TODO: обновился ключ у хоста -- что делать?
    //} else {
    //    hosts.insert(std::pair<Host, public_type>(host, pubkey));
    //    ar = arAppended;
    //}
    //if(hosts.find(host) == hosts.end()) ar = arNotAppended;
    if(ar == arAppended) {
        logger.log("Address appended: %s:%d, total hosts %lu",
                   inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), hosts.size());
    }
    m.unlock();
    return ar;
}

bool Hosts::removeHost(const sockaddr_in &addr, const ADDR_TYPE &addr_type) {
    bool result = false;
    m.lock();
    Host host(addr, addr_type);
    auto it = hosts.find(host);
    if(it != hosts.end())
        hosts.erase(host);
    result = (hosts.find(host) == hosts.end());
    m.unlock();
    return result;
}

size_t Hosts::getHostsCount() {
    size_t count = 0;
    m.lock();
    count = hosts.size();
    m.unlock();
    return count;
}

bool Hosts::getHost(const size_t index, sockaddr_in &addr, public_type &pubkey, ADDR_TYPE &addr_type) {
    m.lock();
    if(index < hosts.size()) {
        size_t counter = 0;
        for (auto it = hosts.begin(); it != hosts.end(); ++it) {
            if (counter == index) {
                pubkey.from(it->second);
                addr = it->first.address;
                addr_type = it->first.addr_type;
                m.unlock();
                return true;
            }
            counter++;
        }
    }
    ZEROIZE(&addr);
    ZEROIZE(&pubkey);
    addr_type = atUnknown;
    m.unlock();
    return false;
}

bool Hosts::getHost(public_type &pubkey, const sockaddr_in &addr, const ADDR_TYPE &addr_type) {
    m.lock();
    Host host(addr, addr_type);
    auto it = hosts.find(host);
    if(it != hosts.end()) {
    	pubkey = it->second;
        m.unlock();
        return true;
    } else {
        //ZEROIZE(&addr);
        //addr_type = atUnknown;
        m.unlock();
        return false;
    }
}

void Hosts::clear() {
    m.lock();
    hosts.clear();
    m.unlock();
}
bool Hosts::getMainHost() {
	return (mainHost != nullptr);
}
bool Hosts::getMainHost(sockaddr_in &addr) {
	public_type pkey;
	ADDR_TYPE atp;
	return getMainHost(pkey, addr, atp);
}
bool Hosts::getMainHost(public_type &pubkey,  sockaddr_in &addr,  ADDR_TYPE &addr_type) {
	bool retcode = false;
	m.lock();
	if (mainHost != nullptr)
	{
		auto mhst = hosts.find(*mainHost);
		if (mhst != hosts.end())
		{
			pubkey = mhst->second;
			addr = mhst->first.address;
			addr_type = mhst->first.addr_type;
			retcode = true;
		}
	}
	m.unlock();
	return retcode;
}

bool Hosts::setMainHost(sockaddr_in addr) {
	Host r = Host(addr, ADDR_TYPE::atUnknown);
	bool retcode = false;
	m.lock();
	auto f = hosts.find(r);
	if (f != hosts.end())
	{
		mainHost =(PHosts)& f->first;
		retcode = true;
	}
	else
	{
		hosts.insert(std::pair<Host, public_type>(r, public_type()));
		auto f = hosts.find(r);
		if (f != hosts.end())
		{
			mainHost = (PHosts)& f->first;
			retcode = true;
		}
	}
	m.unlock();
	return retcode;
}
