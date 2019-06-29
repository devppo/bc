#include "net.h"
#include "proto.h"
#include "../database/blocks_thread.h"
//------------------------------------------------------------------------------
#include <event2/event.h>
#include <event2/listener.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>

#ifdef _WIN32
#pragma comment(lib, "../contrib/event2/libevent.lib")
#endif
//------------------------------------------------------------------------------
void on_read(evutil_socket_t fd, short flags, void *arg);
void on_write(evutil_socket_t fd, short flags, void *arg);
void on_timer(evutil_socket_t fd, short kind, void *arg);
void on_bufftimer(evutil_socket_t fd, short kind, void *arg);

typedef struct NetContext {
    NetContext(const public_type &ownPub,
               const private_type &ownPriv,
               const char *host = nullptr,
               const unsigned short port = UDP_PORT) : sin{},
                                                       fd(-1),
                                                       base(nullptr),
                                                       write_event(nullptr),
                                                       read_event(nullptr),
                                                       timer_event(nullptr)
    {
        ctxPubkey = ownPub;
        ctxPrivKey = ownPriv;

#ifdef _WIN32
		WORD wVersionRequested = MAKEWORD(2, 2);
		WSADATA wsaData;
		if (WSAStartup(wVersionRequested, &wsaData)) {
			logger.err("Networking initialization error 0x%08X", WSAGetLastError());
			throw std::runtime_error("Network initialization error");
		}
		else {
			logger.dbg("WSAStartup initialization success");
		}
#endif

		fd = socket(AF_INET, SOCK_DGRAM, 0);
		if (fd < 0) {
			fd = -1;
#ifdef _WIN32
			logger.err("Socket initialization error 0x%08X", WSAGetLastError());
#else
			logger.err("Socket initialization error 0x%08X", errno);
#endif
			throw std::runtime_error("Socket initialization error");
		}
		if (evutil_make_socket_nonblocking(fd) < 0) {
			CLOSESOCKET(fd);
			fd = -1;
            throw std::runtime_error("Socket evutil initialization error");
		}

		ZEROIZE(&ctxSin);
		ctxSin.sin_family = AF_INET;
		ctxSin.sin_port = htons(port ? port : UDP_PORT);
		ctxSin.sin_addr.s_addr = (host && strlen(host)) ? inet_addr(host) : INADDR_ANY;


		// TODO: 
		/*
		sin = { 0 };
		ZEROIZE(&sin);
		sin.sin_family = AF_INET;
		sin.sin_port = htons(port ? port : UDP_PORT);
		sin.sin_addr.s_addr = (host && strlen(host)) ? inet_addr(host) : INADDR_ANY;
		// ВРЕМЕННО
		DEF_ADDR = sin.sin_addr.s_addr;
		*/

#ifndef _WIN32
		{
			int one = 1;
			if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) < 0) {
				logger.err("setsockopt error 0x%08X", errno);
                CLOSESOCKET(fd);
                fd = -1;
                throw std::runtime_error("Socket flags error");
			}
			else {
				logger.dbg("setsockopt success");
			}
		}
#endif
#ifdef TARGET_OS_MAC
		if (::bind(fd, (struct sockaddr*)&sin, sizeof(sin)) < 0) {
#else
		if (bind(fd, (struct sockaddr*)&ctxSin, sizeof(ctxSin)) < 0) {
#endif
#ifdef _WIN32
			logger.err("Bind error 0x%08X", WSAGetLastError());
#else
			logger.err("Bind error 0x%08X (%s)", errno, strerror(errno));
#endif
			CLOSESOCKET(fd);
			fd = -1;
            throw std::runtime_error("Socket bind error");
		}
		else {
			logger.dbg("bind success");
		}


		base = event_base_new();
		if (base) {
			read_event = event_new(base, fd, EV_READ | EV_PERSIST,
				on_read, (void *)this);
			if (read_event) {
				write_event = event_new(base, fd, EV_WRITE | EV_PERSIST,
					on_write, (void *)this);
				if (write_event) {
					timer_event = evtimer_new(base, on_timer, (void *)this);
					if (timer_event) {
						if (!event_add(read_event, nullptr)) {
							return;
						}
						event_free(timer_event);
						timer_event = nullptr;
					}
					event_free(write_event);
					write_event = nullptr;
				}
				event_free(read_event);
				read_event = nullptr;
			}
			event_base_free(base);
			base = nullptr;
		}
		CLOSESOCKET(fd);
		fd = -1;
        throw std::runtime_error("Socket events initialization error");
    }

	~NetContext() {
		logger.dbg("NetContext destroy...");
		try {
			logger.dbg("close socket...");
			if (fd >= 0) CLOSESOCKET(fd);
			logger.dbg("deleting event_read...");
			if (read_event) {
				event_del(read_event);
				event_free(read_event);
			}
			logger.dbg("deleting event_write...");
			if (write_event) {
				event_del(write_event);
				event_free(write_event);
			}
			logger.dbg("deleting event_timer...");
			if (timer_event) {
				evtimer_del(timer_event);
				event_free(timer_event);
			}
			logger.dbg("deleting base event...");
			if (base) event_base_free(base);
		}
		catch (const std::exception &e) {
			logger.exc("network context destructor: %s", e.what());
		}
#ifdef _WIN32
		if (WSACleanup() == SOCKET_ERROR) {
			logger.err("WSACLeanup error 0x%08X", WSAGetLastError());
		}
#endif
	}
	struct sockaddr_in sin;
	public_type ctxPubkey;
    private_type ctxPrivKey;
	struct sockaddr_in ctxSin{};

	evutil_socket_t fd;

	struct event_base* base;
	struct event *write_event;
	struct event *read_event;
	struct event *timer_event;
	struct event *bufftimer_event=nullptr;

	bool launch_timer();
	bool SendTo(unsigned char *Data, size_t DataSz, sockaddr_in &addr);
} *PNetContext, *HNetContext;
//------------------------------------------------------------------------------
#define RECV_LOCK rm.lock()
#define RECV_UNLOCK rm.unlock()
#define SEND_LOCK sm.lock()
#define SEND_UNLOCK sm.unlock()

#define BUF_PTR(ptr, sz)    std::shared_ptr<unsigned char> ptr(new unsigned char[sz], std::default_delete<unsigned char[]>())
//------------------------------------------------------------------------------
void on_close(PNetContext pctx);

void ra_net_proc(const public_type &ownPub,
                 const private_type &ownPriv,
                 const char *host = nullptr, unsigned short port = UDP_PORT);
bool prepare_to_send(unsigned char *Data, size_t DataSz, char *host, unsigned short port = UDP_PORT,ENTITY_DATA_TYPE dt=edtBlock);
//------------------------------------------------------------------------------
const struct timeval one_sec = { 0, 100000 };
static std::atomic_bool online(false);
PNetContext PCtx = nullptr;
//------------------------------------------------------------------------------
//struct event_base * buf_timers_base=nullptr;
//------------------------------------------------------------------------------
static struct {
private:
    std::mutex rm;
    std::mutex sm;
//Data exchange types
    typedef std::tuple<std::shared_ptr<unsigned char>, size_t, sockaddr_in, ENTITY_DATA_TYPE> BufTuple;
    typedef std::deque<BufTuple> BufDeque;
    //typedef std::map<hash_type, std::shared_ptr<PACKAGE_BUFFER>> PkgBufMap;
//Data exchange buffers
    BufDeque to_send;
    PkgBufMap package_buffers;
//Commands exchange types
    //NOTE: data fields are commented due to current commands set does not require additional data
    typedef std::tuple<ProtoCommands, CmdStruct, /* std::shared_ptr<unsigned char>, size_t ,*/ sockaddr_in> CmdBufTuple;
    typedef std::deque<CmdBufTuple> CmdBufDeque;
//Commands exchange buffers
    CmdBufDeque commands_to_send;
    CmdBufDeque commands_received;
public:
	void recv_lock() {		RECV_LOCK;	}
	void recv_unlock() { RECV_UNLOCK; }
	size_t get_pcgbuf_count() { return package_buffers.size(); }
	//deque by repeatedly send parts of block

	
	
    bool init_pkg_buffer(PACKAGE_HEADER &header,sockaddr_in &sender) {
        bool result = false;
        RECV_LOCK;
        try {
            //TODO: (#78): if (!package_buffers.size()) if (!event_initialized(event)) - initialize event handler of package_buffers
			if (!package_buffers.size()) {
				if (PCtx->bufftimer_event ==nullptr)
					add_buftimer(buffer_fill_timeout, (void *)&package_buffers);
			}
			auto it = package_buffers.find(header.cmd_data.total_hash);
            if (it == package_buffers.end()) {
                package_buffers.insert(std::pair<hash_type,
					std::shared_ptr<PACKAGE_BUFFER>>(header.cmd_data.total_hash,
                                                    new PACKAGE_BUFFER(header)));
				auto that = package_buffers.find(header.cmd_data.total_hash);
				if (that != package_buffers.end() /*&& header.data_type==edtBlock*/) {
					sprintf(that->second.get()->sender.host, "%s", inet_ntoa(sender.sin_addr));
					that->second.get()->sender.port = ntohs(sender.sin_port);
					//that->second.get()->timer_event = add_buftimer(buffer_fill_timeout, that->second.get());
					
				}
				
            } else {
                logger.warn("buffer already exists");
            }
			it = package_buffers.find(header.cmd_data.total_hash);
			result = (it != package_buffers.end());			

        } catch(const std::exception &e) {
            logger.exc("init_pkg_buffer: %s", e.what());
            result = false;
        }
        RECV_UNLOCK;
        return result;
    }
    appendResult append_pkg_part(PACKAGE_PART &part) {
        auto result = arUndefined;
        RECV_LOCK;
        try {
            logger.dbg("append_pkg_part: Package buffers %lu", package_buffers.size());
            auto it = package_buffers.find(part.header.total_hash);
            if (it != package_buffers.end()) {
                HPACKAGE_BUFFER hBuffer = it->second.get();
                if (hBuffer->completed()) {
                    logger.dbg("Buffer already completed\n");
                    result = arAlreadyExists;
                } else {
                    result = hBuffer->appendPart(part) ? arAppended : arNotAppended;
                }
            } else {
                logger.err("append_pkg_part: part buffer not found");
                result = arNotAppended;
            }
        } catch(const std::exception &e) {
            logger.exc("append_pkg_part: %s", e.what());
            result = arNotAppended;
        }
        RECV_UNLOCK;
        return result;
    }
	std::shared_ptr<unsigned char> extract_received(size_t &sz,ENTITY_DATA_TYPE &dtp) {
        RECV_LOCK;
        try {
            for (auto &package_buffer : package_buffers) {
                auto &pkg_buffer = *package_buffer.second.get();
                auto total_hash = pkg_buffer.getHeader()->cmd_data.total_hash;
				dtp = pkg_buffer.getHeader()->data_type;
                logger.dbg("Extracting data");
                 auto data = pkg_buffer.getData(sz);
                if (data && sz) {
                    logger.dbg("Data extracted");
                    logger.dbg("Package buffers before erase %lu", package_buffers.size());
                    package_buffers.erase(total_hash);
                    logger.dbg("Package buffers after erase %lu", package_buffers.size());
                    RECV_UNLOCK;
                    return data;
                }
            }
        } catch(const std::exception &e) {
            logger.exc("extract_received: %s", e.what());
        }
        RECV_UNLOCK;
        return nullptr;
    }
//Data send implementation
    size_t append_to_send(const unsigned char *Data, const size_t DataSz, sockaddr_in &addr, ENTITY_DATA_TYPE data_type=edtBlock) {
        SEND_LOCK;
        try {
            BUF_PTR(Ptr, DataSz);
            memcpy(Ptr.get(), Data, DataSz);
            /*
             * b_empty flags defines activity of on_write event;
             * it checks both data and command buffers for empty
             */
#ifndef MAX_DEQUE
#define MAX_DEQUE (~(size_t)0)
#endif
			bool b_empty = to_send.empty() && commands_to_send.empty();
			if (to_send.size() < MAX_DEQUE) {
				to_send.emplace_back(BufTuple(Ptr, DataSz, addr, data_type));
			}
            if (!to_send.empty() && b_empty) {
                //If on_write was inactive and there is new data to send then activate on_write
                event_add(PCtx->write_event, nullptr);
            } else 
				if (!to_send.empty() && !event_pending(PCtx->write_event,EV_WRITE,nullptr))
					event_add(PCtx->write_event, nullptr);
        } catch(const std::exception &e) {
            logger.exc("append_to_send: %s", e.what());
        }
		auto s = to_send.size();
        SEND_UNLOCK;
		return s;
    }

	std::shared_ptr<unsigned char> extract_to_send(size_t &sz, sockaddr_in &addr, ENTITY_DATA_TYPE &data_type) {
		std::shared_ptr<unsigned char> ptr = nullptr;
        SEND_LOCK;
        try {
            if (to_send.empty()) {
                SEND_UNLOCK;
                sz = 0;
                return nullptr;
            }
            auto result = to_send.front();
            to_send.pop_front();
            ptr = std::get<0>(result);
            sz = std::get<1>(result);
            addr = std::get<2>(result);
			data_type = std::get<3>(result);
        } catch(const std::exception &e) {
            logger.exc("extract_to_send: %s", e.what());
        }
        SEND_UNLOCK;
        return ptr;
    }
//Commands send implementation
    //NOTE: data args are commented due to current commands set does not require additional data
    size_t append_command_to_send(ProtoCommands cmd, CmdStruct &cmd_data, /*const unsigned char *Data, const size_t DataSz,*/ sockaddr_in &addr) {
        SEND_LOCK;
        try {
            switch(cmd)
            {
                case protoIam:
                case protoIamtoo:
                case protoHeIs:
                case protoGetEntity:
				case protoLastHash:
				case protoGetRoundINFO:
				case protoSendRoundINFO:
				case protoGetEntityPart:
				case protoGetRestoreChain:
                {
                    //BUF_PTR(Ptr, DataSz);
                    //memcpy(Ptr.get(), Data, DataSz);
                    /*
                     * b_empty flags defines activity of on_write event;
                     * it checks both data and command buffers for empty
                     */
#ifndef MAX_CMD_DEQUE
#define MAX_CMD_DEQUE (~0)
#endif                    
					bool b_empty = to_send.empty() && commands_to_send.empty();
					if (commands_to_send.size() < MAX_CMD_DEQUE)
						commands_to_send.emplace_back(CmdBufTuple(cmd, cmd_data,/* Ptr, DataSz, */ addr));
                    
                    if (!commands_to_send.empty() && b_empty) {
                        //If on_write was inactive and there is new command to send then activate on_write
                        event_add(PCtx->write_event, nullptr);
                    }
					else
						if (!commands_to_send.empty() && !event_pending(PCtx->write_event, EV_WRITE, nullptr))
							event_add(PCtx->write_event, nullptr);
                    break;
                }
                default:
                    break;
            }
        } catch(const std::exception &e) {
            logger.exc("append_command_to_send: %s", e.what());
        }
		auto s = commands_to_send.size();
		SEND_UNLOCK;
        return s;
    }
    ProtoCommands extract_command_to_send(CmdStruct &cmd_data, sockaddr_in &addr) {
        ProtoCommands cmd = protoNoCommand;
        SEND_LOCK;		
        try {
            if (commands_to_send.empty()) {
                SEND_UNLOCK;
                return protoNoCommand;
            }
            auto result = commands_to_send.front();
            commands_to_send.pop_front();
            cmd = std::get<0>(result);
            cmd_data = std::get<1>(result);
            addr = std::get<2>(result);
        } catch(const std::exception &e) {
            logger.exc("extract_command_to_send: %s", e.what());
            cmd = protoUndefined;
        }
        SEND_UNLOCK;
        return cmd;
    }
    size_t append_command_received(const ProtoCommands cmd, CmdStruct &cmd_data, sockaddr_in &addr) {
        size_t result = 0;
        RECV_LOCK;
        try {
            commands_received.emplace_back(CmdBufTuple(cmd, cmd_data, addr));
            result = commands_received.size();
#ifdef MAX_CMD_DEQUE
            if (result > MAX_CMD_DEQUE) {
                commands_received.pop_front();
                result--;
            }
#endif
        } catch(const std::exception &e) {
            logger.exc("append_command_received: %s", e.what());
        }
        RECV_UNLOCK;
        logger.dbg("append_command_received: cmd %d, received commands deque size %d", cmd, result);
        return result;
    }
    ProtoCommands extract_command_received(CmdStruct &cmd_data, sockaddr_in &addr) {
        ProtoCommands result = protoNoCommand;
        RECV_LOCK;
        try {
            if (commands_received.empty()) {
                RECV_UNLOCK;
                return result;
            }
            auto command_received = commands_received.front();
            result = std::get<0>(command_received);
            cmd_data = std::get<1>(command_received);
            addr = std::get<2>(command_received);
            commands_received.pop_front();
        } catch(const std::exception &e) {
            logger.exc("extract_command_received: %s", e.what());
            result = protoInvalid;
        }
        RECV_UNLOCK;
        return result;
    }
	
	void erase_unactual_buffer(hash_type hash_id) {
		//RECV_LOCK;
		try {
			package_buffers.erase(hash_id);
		}
		catch (const std::exception &e) {
			//skip
		}
		//RECV_UNLOCK;
	}
} SendRecvDeques;
//------------------------------------------------------------------------------
bool NetContext::launch_timer() {
	if (evtimer_add(timer_event, &one_sec) < 0) {
		logger.err("NetContext::launch_timer: evtimer_add error 0x%08X", errno);
		return false;
	}
	else {
		logger.dbg("NetContext::launch_timer: evtimer_add success");
		return true;
	}
}

bool NetContext::SendTo(unsigned char *Data, size_t DataSz, sockaddr_in &addr) {
    try {
		socklen_t serverlen = sizeof(addr);
        size_t sent = 0;
        while (sent < DataSz) {
            auto n = sendto(fd, (const char *)(Data + sent), DataSz - sent, 0, (const sockaddr *) &addr, serverlen);
            if (n < 0) {
                logger.err("NetContext::SendTo error %d", errno);
                //if(errno == EAGAIN) continue;
                //CLOSESOCKET(fd);
                //return false;
                break;
            }
            if (n == 0) 
				break;
            sent += n;
        }
        return true;
    } catch(const std::exception &e) {
        logger.exc("NetContext::SendTo: %s", e.what());
		return false;
    }
}
//------------------------------------------------------------------------------
bool prepare_to_send(unsigned char *Data, size_t DataSz, char *host, unsigned short port,ENTITY_DATA_TYPE dt) {
    try {
        if (!Data) {
            logger.err("prepare_to_send: no data");
            return false;
        }
        if (!DataSz) {
            logger.err("prepare_to_send: zero size data");
            return false;
        }
        if (!host) {
            logger.err("prepare_to_send: no host");
            return false;
        }
        if (!port) {
            //logger.err("prepare_to_send: no port");
            //return false;
            port = UDP_PORT;
        }
        struct sockaddr_in sin{};
        ZEROIZE(&sin);
        sin.sin_family = AF_INET;
        sin.sin_port = htons(port);
        sin.sin_addr.s_addr = inet_addr(host);
        if (sin.sin_addr.s_addr == INADDR_NONE) return false;

        SendRecvDeques.append_to_send(Data, DataSz, sin,dt);
//        hosts.appendHost(sin);
        return true;
    } catch(const std::exception &e) {
        logger.exc("prepare_to_send: %s", e.what());
    }
    return false;
}

bool net_recv(unsigned char *Buffer,
			  size_t &BufferSz, ENTITY_DATA_TYPE &edata_type,
			  char *Status, size_t StatusSz)
{
	if (!online) {
		sprintf(Status, "No received data available");
		return false;
	}
	SILENCE
    try {
        size_t data_sz = 0;
        auto data = SendRecvDeques.extract_received(data_sz, edata_type);
        if (data && data_sz) {
            if (data_sz <= BufferSz) {
                BufferSz = data_sz;
				switch (edata_type) 
				{
					case edtBlock:
					case edtEntityParts:
						memcpy(Buffer, data.get(), data_sz);
						break;
					case edtTransaction:
					{
						//append or receive redirected transaction
						Transaction *r_tran;
						r_tran = (Transaction *)data.get();
						if (r_tran->valid()) {
							sockaddr_in sin{};
							if (hosts.getMainHost(sin)) {
								if (sin == get_self_sin()) {
									if (db_singleton.appendTransaction(*r_tran, Status, StatusSz))
										logger.dbg("redirected transaction been appended");
									else
										logger.err("redirected transaction not been appnded");
								}
								else {
									if (!net_sendto(inet_ntoa(sin.sin_addr), sin.sin_port, (unsigned char *) r_tran,
													sizeof(Transaction), edtTransaction))
										logger.err("Redirect transaction error by node %s:%u", inet_ntoa(sin.sin_addr), htons(sin.sin_port));
								}
							}
							else {
								logger.err("Redirected transaction was received, but ROUND not been set!");
							}
						}
						else {
							logger.err("Redirected transaction was received, but it is not valid!");
						}
						return false;
						break;
					}
					case edtRestoreChain:
					{
						auto rsh_info = (RestoreChainInfo *)data.get();
						//обработка цепочки, запуск синхронизации
						bool canStart = (db_singleton.hSync.SyncState() != SyncHandler::eSyncLanch);
						if (canStart) {
							db_singleton.hSync.ClearSyncFlg();
							db_singleton.hSync.bottom_hash = db_singleton.GetLastHash();
							db_singleton.hSync.top_hash = rsh_info->final_hash;
						}
						for (size_t i = 0; i < rsh_info->sz; i++) {
							hash_type h = rsh_info->chain[i].hash;
							auto n = rsh_info->chain[i].num;
							if (!db_singleton.hashExists(h))
								db_singleton.hSync.append(h, rsh_info->sender,n);
							
						}
						//db_singleton.hSync.top_hash = rsh_info->chain[rsh_info->sz - 1];
						if (canStart)
						{
							auto sync_thread = new std::thread(net_sync_proc);
							sync_thread->detach();
							if (!sync_thread->joinable())
								logger.dbg("Syncronization started, net_sync_proc loaded");
						}
						break;
					}
					default:
						logger.dbg("Flexible data was received, %u size", data_sz);
						memcpy(Buffer, data.get(), data_sz);
						break;
				} //end switch
				return true;				
            } else {
                SPRINTF(Status, "Insufficient buffer size to get received data; 64K buffer recommended; data lost");
                return false;
            }
        } else {
            SPRINTF(Status, "No received data available");
            return false;
        }
    } catch(const std::exception &e) {
        logger.exc("net_recv: %s", e.what());
		return false;
    }
}

bool net_sendto(char *host, unsigned short port,
				unsigned char *Data, size_t DataSz, ENTITY_DATA_TYPE dt,
				char *Status, size_t StatusSz)
{
    SILENCE

    try {
        if (PCtx) {
            return prepare_to_send(Data, DataSz, host, port,dt);
        } else {
            SPRINTF(Status, "net_sendto: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        logger.exc("net_sendto: %s", e.what());
		return false;
    }
}

/*
 * Узел представляется другому узлу, отправляя ему свой идентификатор и публичный ключ.
 * Получив такой пакет узел ответит вопрошающему свой iam и перешлёт его запрос по своей подсети.
 * В результате, новому узлу представится вся подсеть, а он из них соберёт свою подсеть.
 */
bool net_command_iam(const char *host, unsigned short port,
					 char *Status, size_t StatusSz)
{
    SILENCE

    //logger.dbg("net_command_iam");
    try {
        if (PCtx) {
            if (!host) {
                logger.err("net_command_iam: no host");
                return false;
            }
            struct sockaddr_in sin{};
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
			sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.my_data.my_public = PCtx->ctxPubkey;			
            //cmd_data.my_data.random_data = seed_type();
			cmd_data.my_data.chainid_hash = hash_type();
			db_singleton.getChainIdHash(&cmd_data.my_data.chainid_hash);

            //ed25519_create_seed(cmd_data.my_data.random_data.data, seed_type::get_sz());//Seed size is 0x20 bytes
            return SendRecvDeques.append_command_to_send(protoIam, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "net_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        logger.exc("net_command_iam: %s", e.what());
        return false;
    }
}

bool net_command_iamtoo(const char *host, unsigned short potr,
						char *Status, size_t StatusSz)
{
	SILENCE

	//logger.dbg("net_command_iamtoo")
	try {
		/*if (PCtx) {*/
			if(!host) {
				logger.err("net_command_iamtoo: no host");
				return false;
			}
			struct sockaddr_in sin{};
			ZEROIZE(&sin);
			sin.sin_family = AF_INET;
			sin.sin_port = htons(potr ? potr : UDP_PORT);
			sin.sin_addr.s_addr = inet_addr(host);
			if (sin.sin_addr.s_addr == INADDR_NONE) return false;
			//CmdStruct cmd_data;
			//cmd_data.my_data.my_public = PCtx->ctxPubkey;
			//cmd_data.my_data.random_data = seed_type();
			//ed25519_create_seed(cmd_data.my_data.random_data.data, seed_type::get_sz());
			return net_command_iamtoo(sin, Status, StatusSz);
			//return SendRecvDeques.append_command_to_send(protoIamtoo, cmd_data, sin) > 0;
		/*}
		else {
			SPRINTF(Status, "net_command_iamtoo: Networking context is not initialized");
			return false;
		}*/
	} catch (const std::exception &e) {
		logger.exc("net_command_iamtoo: %s", e.what());
		return false;
	}
}
bool net_command_iamtoo(sockaddr_in addr, char *Status, size_t StatusSz) {
	SILENCE
	if (PCtx) {
		if (addr.sin_addr.s_addr == INADDR_NONE) return false;
		CmdStruct cmd_data;
		cmd_data.my_data.my_public = PCtx->ctxPubkey;
		return SendRecvDeques.append_command_to_send(protoIamtoo, cmd_data, addr) > 0;
	}
	else {
		SPRINTF(Status, "net_command_iamtoo: Networking context is not initialized");
		return false;
	}
}

bool net_command_heis(const char *host, unsigned short port,
					  public_type &his_pub,
					  const char *his_host,
					  unsigned short his_port,
					  char *Status, size_t StatusSz)
{
    SILENCE

    //logger.dbg("net_command_heis");
    try {
        if (PCtx) {
            if (!host) {
                logger.err("net_command_heis: no host");
                return false;
            }
            struct sockaddr_in sin{};
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.his_data.his_public = his_pub;
            cmd_data.his_data.addr_type = atUnknown;//TODO: fix
            cmd_data.his_data.his_addr.in.sin_family = AF_INET;
            cmd_data.his_data.his_addr.in.sin_addr.s_addr = inet_addr(his_host);//TODO: use inet_aton with linux
            cmd_data.his_data.his_addr.in.sin_port = htons(his_port);
            return SendRecvDeques.append_command_to_send(protoHeIs, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "net_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        logger.exc("net_command_heis: %s", e.what());
        return false;
    }
}

/*
 * Пакет содержит ключ (хэш) сущности базы данных и отправляется узлам подсети.
 * Получившие этот запрос проверяют, если у них эта сущность отсутствует -- передает запрос
 * своей подсети, исключая того, от кого этот запрос пришёл.
 */
bool net_command_get_entity(const char *host, unsigned short port, hash_type &entity_hash,
							char *Status, size_t StatusSz)
{
    SILENCE

    //logger.dbg("net_command_get_entity");
    try {
        if (PCtx) {
            if (!host) {
                logger.err("net_command_get_entity: no host");
                return false;
            }
            struct sockaddr_in sin{};
            ZEROIZE(&sin);
            sin.sin_family = AF_INET;
            sin.sin_port = htons(port ? port : UDP_PORT);
            sin.sin_addr.s_addr = inet_addr(host);
            if (sin.sin_addr.s_addr == INADDR_NONE) return false;

            CmdStruct cmd_data;
            cmd_data.entity_hash = entity_hash;
            return SendRecvDeques.append_command_to_send(protoGetEntity, cmd_data, sin) > 0;
        } else {
            SPRINTF(Status, "net_command_iam: Networking context is not initialized");
            return false;
        }
    } catch(const std::exception &e) {
        logger.exc("net_command_get_entity: %s", e.what());
        return false;
    }
}

bool net_command_lasthash(const char *host, unsigned short port, char *Status, size_t StatusSz) {
	SILENCE
	if (!host) return false;
	struct sockaddr_in sin{};
	ZEROIZE(&sin);
	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(host);
	if (sin.sin_addr.s_addr == INADDR_NONE) return false;
	return net_command_lasthash(sin, Status, StatusSz);
}
bool net_command_lasthash(sockaddr_in addr, char *Status, size_t StatusSz) {
	SILENCE
	if (!PCtx) return false;
	hash_type lh = db_singleton.GetLastHash();
	CmdStruct cmd_data;
	cmd_data.total_hash = lh;
	return SendRecvDeques.append_command_to_send(protoLastHash, cmd_data, addr) > 0;
}

bool net_command_getroundinfo(const char *host, unsigned short port) {
	if (!host) return false;
	sockaddr_in s{};
	ZEROIZE(&s);
	s.sin_family = AF_INET;
	s.sin_port = port;
	s.sin_addr.s_addr = inet_addr(host);
	if (s.sin_addr.s_addr == INADDR_NONE) return false;
	return net_command_getroundinfo(s);
}
bool net_command_getroundinfo(sockaddr_in addr) {
	if (!PCtx) return false;
	CmdStruct cmd_data;
	return SendRecvDeques.append_command_to_send(protoGetRoundINFO, cmd_data, addr) > 0;
}

bool net_command_sendroundinfo(const char *host, unsigned short port) {
	sockaddr_in s{};
	ZEROIZE(&s);
	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = inet_addr(host);
	if (s.sin_addr.s_addr == INADDR_NONE) return false;
	return net_command_sendroundinfo(s);
}
bool net_command_sendroundinfo(sockaddr_in addr) {
	if (!PCtx) return false;
	CmdStruct cmd_data;
	if (hosts.getMainHost(cmd_data.his_data.his_public, cmd_data.his_data.his_addr.in, cmd_data.his_data.addr_type))
		return SendRecvDeques.append_command_to_send(protoSendRoundINFO, cmd_data, addr) > 0;
	else
		return false;
}


bool net_command_get_entitypart(const char *host, unsigned short port, hash_type &entity_hash, uint16_t offset,
								uint16_t parts_count,
								char *Status, size_t StatusSz) {
	sockaddr_in s{};
	ZEROIZE(&s);
	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = inet_addr(host);
	return net_command_get_entitypart(s, entity_hash, offset, parts_count, Status, StatusSz);
	/*if (s.sin_addr.s_addr == INADDR_NONE) return false;
	CmdStruct cmd_data;
	cmd_data.entity_part_data.entity_hash = entity_hash;
	cmd_data.entity_part_data.offset = offset;
	cmd_data.entity_part_data.count = parts_count;
	return SendRecvDeques.append_command_to_send(protoGetEntityPart, cmd_data, s) > 0;*/
}

bool net_command_get_entitypart(sockaddr_in addr, hash_type &entity_hash, uint16_t offset, uint16_t parts_count,
								char *Status, size_t StatusSz) {

	if (addr.sin_addr.s_addr == INADDR_NONE) return false;
	CmdStruct cmd_data;
	cmd_data.entity_part_data.entity_hash = entity_hash;
	cmd_data.entity_part_data.offset = offset;
	cmd_data.entity_part_data.count = parts_count;
	return SendRecvDeques.append_command_to_send(protoGetEntityPart, cmd_data, addr) > 0;

}

bool net_command_get_restorechain(const char *host, unsigned short port, hash_type &last_hash, int part) {
	sockaddr_in s{};
	ZEROIZE(&s);
	s.sin_family = AF_INET;
	s.sin_port = htons(port);
	s.sin_addr.s_addr = inet_addr(host);
	if (s.sin_addr.s_addr == INADDR_NONE) return false;
	return net_command_get_restorechain(s, last_hash, part);
	
}
bool net_command_get_restorechain(sockaddr_in addr, hash_type &last_hash, int part) {
	if (!PCtx) return false;
	CmdStruct cmd_data;
	cmd_data.entity_part_data.entity_hash = last_hash;
	if (part != -1) {
		cmd_data.entity_part_data.count = 1;
		cmd_data.entity_part_data.offset = part;
	}
	else {
		cmd_data.entity_part_data.count = 0;
		cmd_data.entity_part_data.offset = 0;
	}

	return SendRecvDeques.append_command_to_send(protoGetRestoreChain, cmd_data, addr) > 0;
}

//bool ra_command_send_entitypart(CmdStruct &cmd_data, sockaddr_in &addr) {
//	SendRecvDeques.RepeatCmdDeque.emplace_back(RepeadBufTuple(cmd_data, addr));
//	return true;
//}

bool net_round_broadcast() {
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	auto hosts_sz = hosts.getHostsCount();
	auto self_sin = get_self_sin();
	CmdStruct cmd_data;
	if (!hosts.getMainHost(cmd_data.his_data.his_public, cmd_data.his_data.his_addr.in, cmd_data.his_data.addr_type))
	{
		//logger.err("No define main round host in hosts list");
		return false;
	}
	if (hosts_sz != 0) {
		for (size_t i = 0; i < hosts_sz; ++i) {
			sockaddr_in sin{};
			public_type key;
			ADDR_TYPE type;
			auto result = hosts.getHost(i, sin, key, type);
			if (result) {
				if (!(
					(self_sin.sin_addr.s_addr == sin.sin_addr.s_addr) &&
					(self_sin.sin_port == sin.sin_port)
					))
				{
					auto addr = inet_ntoa(sin.sin_addr);
					if (!SendRecvDeques.append_command_to_send(protoSendRoundINFO, cmd_data, sin)) {
						logger.err("Not add 'Send round INFO' command for host %s, port %d : %s", addr, ntohs(sin.sin_port), Status);
						return false;
					}
				}
			}
		}
		return true;
	}
	else {
		logger.err("No defined hosts in hosts list");
		return false;
	}
}
/*
 * Представление со всем списком своих хостов.
 * Отправляет команду iam своему списку хостов.
 * От каждого хоста ожидается такая же команда в ответ.
 */
bool net_present_me() {
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	size_t SizeT = 0;
	auto hosts_sz = hosts.getHostsCount();
	auto self_sin = get_self_sin();
	if (hosts_sz != 0) {
		for(size_t i = 0; i < hosts_sz; ++i) {
			sockaddr_in sin{};
			public_type key;
			ADDR_TYPE type;
			auto result = hosts.getHost(i, sin, key, type);
			if(result) {
				if (!(
					(self_sin.sin_addr.s_addr == sin.sin_addr.s_addr) &&
					(self_sin.sin_port == sin.sin_port)
					))
				{
					char addr[16] = { '\0' };
					sprintf(addr, "%s", inet_ntoa(sin.sin_addr));
					//auto addr = inet_ntoa(sin.sin_addr);
					if (!net_command_iam(addr, ntohs(sin.sin_port), Status, SizeT)) {
						logger.err("Not add 'I am' command for host %s, port %d : %s", addr, ntohs(sin.sin_port), Status);
						return false;
					}
				}
			}
		}
		return true;
	}
	else {
		logger.err("No defined hosts in hosts list");
		return false;
	}
}

//Event handlers----------------------------------------------------------------
void on_close(PNetContext pctx) {
    try {
        online = false;
        delete pctx;
		logger.dbg("on_stop: context destroyed");
    } catch(const std::exception &e) {
        logger.exc("on_stop: %s", e.what());
    }
}

void on_read(evutil_socket_t fd, short flags, void* arg) {
    try {
        struct sockaddr_in clientaddr{};
        ZEROIZE(&clientaddr);
        socklen_t clientlen = sizeof(clientaddr);

        unsigned char buf[0x10000];
        ZEROARR(buf);
        for (;;) {
            //TODO: memory allocator
			auto n = recvfrom(fd, (char *)buf,
                              COUNT(buf), 0,
                              (sockaddr *) &clientaddr, &clientlen);
			//clientaddr.sin_port = ntohs(clientaddr.sin_port); // add 10.12.2018 обратная перекодировка порта
            if (n == sizeof(PACKAGE_HEADER)) {
//                hosts.appendHost(clientaddr);
                auto hPkgHeader = (HPACKAGE_HEADER) buf;
                if (hPkgHeader->valid()) {
                    switch(hPkgHeader->command)
                    {
                        case protoSendEntity:
							//if (hPkgHeader->data_type == edtBlock) {
								if (SendRecvDeques.init_pkg_buffer(*hPkgHeader,clientaddr)) {
									continue;
								}
							//}
							//else {
								//TODO: get transaction for append
							//}
                            break;
                    	case protoIamtoo:
                        case protoIam:
						case protoHeIs:
                        case protoGetEntity:
						case protoGetEntityPart:
						case protoLastHash:
						case protoGetRoundINFO:
						case protoSendRoundINFO:
						case protoGetRestoreChain:
							SendRecvDeques.append_command_received(hPkgHeader->command, hPkgHeader->cmd_data, clientaddr);
							break;				
                        default:
                            logger.err("Unknown command %d received from %s:%d",
                                    hPkgHeader->command,
                                    inet_ntoa(clientaddr.sin_addr),
                                    ntohs(clientaddr.sin_port));
                            break;
                    }
                } else {
                    logger.err("Broken package header received from %s:%d",
                            inet_ntoa(clientaddr.sin_addr),
                            ntohs(clientaddr.sin_port));
                }
            } else {
				if (n == sizeof(PACKAGE_PART)) {
					auto hPkgPart = (HPACKAGE_PART)buf;
					//int n = hPkgPart->header.N;
					switch (SendRecvDeques.append_pkg_part(*hPkgPart)) {
					case arAppended:
						
						continue;
					case arAlreadyExists:
					case arNotAppended:
					default:
						break;
					}
					
				}
            }
            if (n <= 0) break;
        }
    } catch(const std::exception &e) {
        logger.exc("on_read: %s", e.what());
    }
}

void on_write(evutil_socket_t fd, short flags, void *arg) {
    try {
        auto pctx = (PNetContext) arg;
        size_t DataSz;
        sockaddr_in addr{};
        ZEROIZE(&addr);
		ENTITY_DATA_TYPE data_type;
		ENTITY_PART * ep;
        auto Data = SendRecvDeques.extract_to_send(DataSz, addr,data_type);
		HPACKAGE_BUFFER hp_buffer;
		size_t sDataSz = DataSz;
        if (Data && DataSz) {
			if (data_type == ENTITY_DATA_TYPE::edtEntityParts) {
				ep = (ENTITY_PART *)Data.get();
				unsigned char *p_data;
				db_singleton.interlocked_obtain((unsigned char *)&ep->block, hash_type::get_sz(), p_data, sDataSz);
				BUF_PTR(sData, sDataSz);
				memcpy(sData.get(), p_data, sDataSz);
				hp_buffer=new PACKAGE_BUFFER(sData,sDataSz, pctx->ctxPubkey, pctx->ctxPrivKey, data_type);
			}
			else {
				hp_buffer=new PACKAGE_BUFFER(Data, sDataSz,
					pctx->ctxPubkey, pctx->ctxPrivKey, data_type);
			}
			auto hHeader = hp_buffer->getHeader();
			switch (data_type)
			{
			case edtBlock:
			case edtTransaction:
			case edtEntityParts:
			case edtRestoreChain:
				if (pctx->SendTo((unsigned char *)hHeader, sizeof(*hHeader), addr)) {
					const size_t c_parts_count = hHeader->parts_count();
					for (size_t i = 0; i < c_parts_count; ++i) {
						auto part_ptr = hp_buffer->getPart(i);
						if (data_type == edtEntityParts) {
							if (i>=ep->firstpartnumber && i<(ep->firstpartnumber+ep->offsetpartsnumber))
								pctx->SendTo((unsigned char *)part_ptr.get(), sizeof(PACKAGE_PART), addr);
						}
						else
						{
							pctx->SendTo((unsigned char *)part_ptr.get(), sizeof(PACKAGE_PART), addr);							
						}
						std::this_thread::sleep_for(std::chrono::microseconds(10));

					}
				}
				delete hp_buffer;
				break;
			default:
				break;
			}
        
		} else {
            CmdStruct cmd_data;
            auto cmd = SendRecvDeques.extract_command_to_send(cmd_data, addr);
			if (cmd >= protoIam && cmd < protoCount) {
				PACKAGE_HEADER header(cmd, cmd_data, pctx->ctxPubkey, pctx->ctxPrivKey);
				if (pctx->SendTo((unsigned char *)&header, sizeof(header), addr)) {
					//
				}
				else {
					//
				}
			}
			else 
				event_del(pctx->write_event);
        }
    } catch(const std::exception &e) {
        logger.exc("on_write: %s", e.what());
    }
}

void on_timer(evutil_socket_t fd, short kind, void *arg) {
    try {
        auto pctx = (PNetContext) arg;
        if (!online) {
            logger.dbg("networking stop");
            event_base_loopbreak(pctx->base);
        } else {
//            logger.dbg("networking timer reset");
			if (!evtimer_pending(pctx->timer_event, nullptr)) {
#ifdef _WIN32
				int errNUM = WSAGetLastError();
				if (errNUM)
					logger.err("evtimer_pending error 0x%08X", WSAGetLastError());
				else
					//logger.dbg("evtimer_pending with 0");

#else
				if(errno) {
					//logger.err("evtimer_pending error 0x%08X", errno);
				}
#endif
				if (evtimer_del(pctx->timer_event) < 0) {
#ifdef _WIN32
					logger.err("evtimer_del error 0x%08X", WSAGetLastError());
#else
					logger.err("evtimer_del error 0x%08X", errno);
#endif
				}
				else {
					//logger.dbg("networking timer disable");
				}
				if (evtimer_add(pctx->timer_event, &one_sec) < 0) {
#ifdef _WIN32
					logger.err("evtimer_add error 0x%08X", WSAGetLastError());
#else
					logger.err("evtimer_add error 0x%08X", errno);
#endif
				}
				else {
					//logger.dbg("networking timer readd");
				}
			}
			else {
				logger.dbg("evtimer_pending success");
			}
        }
    } catch(const std::exception &e) {
        logger.exc("on_timer: %s", e.what());
    }
}
//------------------------------------------------------------------------------
void ra_net_cmd_proc() {
    for(;;) {
        if(!online) {
            logger.dbg("network command thread stop");
            break;
        }
        CmdStruct cmd_data;
        sockaddr_in addr{};
        ZEROIZE(&addr);
        ProtoCommands cmd = SendRecvDeques.extract_command_received(cmd_data, addr);
        switch(cmd)
        {
            case protoInvalid:
            {
                logger.err("Commands deque failure, networking stop");
                online = false;
                return;
            }
            case protoNoCommand:
            {
				std::this_thread::sleep_for(std::chrono::milliseconds(5));
                break;
            }
            default:
            {
                logger.dbg("Got command %d from deque", cmd);
                if(handlers_pool.try_command(cmd, cmd_data, addr)) {
                    //logger.log("Command treatment success, next to try");
                } else {
                    logger.err("Command treatment failure, next to try");
                }
                break;
            }
        }
    }
    logger.dbg("network command thread end");
}

void ra_net_proc(const public_type &ownPub,
                 const private_type &ownPriv,
        const char *host,
        const unsigned short port)
{
    if(!PCtx) {
        logger.dbg("initializing network context");
        try {
            PCtx = new NetContext(ownPub, ownPriv, host, port);
        } catch (std::exception &e) {
            logger.exc("Network context initialization failure: %s", e.what());
            PCtx = nullptr;
            return;
        }
    }

    if(PCtx) {
        logger.dbg("network context initialized");
        online = true;

        CMD_HANDLERS_POOL::COMMAND_EMITS emits = {
                net_command_iam,
                net_command_iamtoo,
                net_command_heis,
                net_command_get_entity,
				net_command_lasthash,
				net_command_get_entitypart
        };
        if(handlers_pool.init_emits(emits)) {
            logger.log("Command Handlers pool initialized successfully");
        } else {
            logger.err("Command Handlers pool initialization error");
        }
        std::thread cmd_th(ra_net_cmd_proc);
        cmd_th.detach();
        if(cmd_th.joinable()) {
            logger.err("Command thread launch failure, deinitializing network...");
            delete PCtx;
            online = false;
            PCtx = nullptr;
            return;
        } else {
            //
        }

        PCtx->launch_timer();
        if(event_base_dispatch(PCtx->base) < 0) {
			logger.err("event_base_dispatch error 0x%08X", errno);
		} else {
			logger.err("event_base_dispatch deblocked");
		}
        on_close(PCtx);
        PCtx = nullptr;
    }
	logger.dbg("network thread end");
}

bool net_launch(const public_type &ownPub,
				const private_type &ownPriv,
				const char *host,
				unsigned short port)
{
    logger.dbg("network start");
	std::thread th(ra_net_proc,
            ownPub,
            ownPriv,
	        host,
	        port);
    th.detach();
    return !th.joinable();
}

void net_stop() {
    logger.dbg(online ? "network stopping" : "network stopped already");
    online = false;
}

bool net_available() {
    return online;
}

sockaddr_in get_self_sin() {
	return PCtx->ctxSin;
}
//------------------------------------------------------------------------------
int net_synclasthash() {
	if (!online || !PCtx) {
		logger.err("Network not available");
		return -1;
	}
	else { 
		sockaddr_in hst{};
		public_type pkey;
		ADDR_TYPE atype = ADDR_TYPE::atUnknown;
		char Status[MINIMAL_STATUS_LENGTH] = { '\0' };		
		
		for (size_t i = 0; i < hosts.getHostsCount(); i++) {
			hosts.getHost(i, hst, pkey, atype);
			auto ihost = inet_ntoa(hst.sin_addr);
			auto iport = EASYPORT(hst);
			if ((strcmp(NET_ADDR,ihost) != 0) || ( UDP_PORT != iport)) {
  				return !net_command_lasthash(inet_ntoa(hst.sin_addr), ntohs(hst.sin_port), Status, 0);
				//TODO:2: организовать перебор по хостам ??
				break;
			}
			else
				ZEROIZE(&hst);
		}
		
		return 0;
	}


}

int net_sync_proc() {
	DbSingletone * singleton = &db_singleton;
	hash_type needed_hash;
	ZEROIZE(&needed_hash);
	sockaddr_in sendaddr{};
	public_type pkey;
	ADDR_TYPE atp;

	while (singleton->hSync.SyncState() != SyncHandler::eSyncComplete) {
		if (singleton->hSync.GetNextResponce(&needed_hash, &sendaddr)) {
			if (!singleton->hSync.buffcount_over) {
				if (SendRecvDeques.get_pcgbuf_count() >= 300) //TODO: set as constant
					singleton->hSync.buffcount_over = true;
			}
			else {
				if (SendRecvDeques.get_pcgbuf_count() <= 50) //TODO: set as constant
					singleton->hSync.buffcount_over = false;
			}
			if (!singleton->hSync.buffcount_over)
			{
				if (sendaddr.sin_addr.s_addr == 0) {
					auto hme = NET_ADDR;
					unsigned int portme = UDP_PORT;
					for (size_t i = 0; i < hosts.getHostsCount(); i++) {
						hosts.getHost(i, sendaddr, pkey, atp);
						if (strcmp(hme, EASYHOST(sendaddr)) != 0 || portme != EASYPORT(sendaddr))
							break;

					}

				}
				if (net_command_get_entity(EASYHOST(sendaddr), EASYPORT(sendaddr), needed_hash))
					singleton->hSync.set_GetEntitySended(needed_hash);

			}
			else
				logger.dbg("buffers overflow: %d", SendRecvDeques.get_pcgbuf_count());

		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));		//TODO: time constant
		if (!singleton->hSync.checkQueue()){
			//singleton->state_own_lasthash((unsigned char *)&singleton->hSync.top_hash);
			singleton->checkIntegrityChain(false,true);
			public_type pkey;
			sockaddr_in addr;
			ADDR_TYPE atype;
			for (size_t i = 0; i < hosts.getHostsCount(); i++) {
				if (hosts.getHost(i, addr, pkey, atype)) {
					if (!(addr == get_self_sin()))
						break;
				}
			}
			net_command_lasthash(inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
		}
			
	}
	
	return 1;
}

 event * add_buftimer(timeval tv, void *arg) {
	 PCtx->bufftimer_event = evtimer_new(PCtx->base, on_bufftimer, arg);
	if (PCtx->bufftimer_event) {
		if (!event_add(PCtx->bufftimer_event, &tv))
			return  PCtx->bufftimer_event;
		else return nullptr;
	}
	else
		return nullptr;
}
 void erase_bad_recv_buffer(hash_type hash_id) {
	 SendRecvDeques.erase_unactual_buffer(hash_id);
 }
#define DEF_BUFFFILL_INTERVAL_SEK 10	//TODO: time constant

 void on_bufftimer(evutil_socket_t fd, short kind, void *arg) {
	 //return;
	 event_del(PCtx->bufftimer_event);
	 try
	 {
		 PkgBufMap * buffers = (PkgBufMap *)arg;
		 if (!buffers->size())
		 {
			 evtimer_add(PCtx->bufftimer_event, &buffer_fill_timeout);
			 return;
		 }
		 if (!online)
		 {
			 evtimer_add(PCtx->bufftimer_event, &buffer_fill_timeout);
			 return;
		 }
		 size_t first = 0;
		 size_t count = 0; 
		 hash_type nhash = hash_type();
		 char hst[16] = { '\0' };
		 unsigned int prt = 0;
		 std::list<hash_type> bufs_to_erase;
		 SendRecvDeques.recv_lock();
		 for (auto buff : *buffers) {
			 if (buff.second->valid())
				 if ((buff.second->sender.host[0] != '-') /*&& (buff.second->timemark)*/) {
					 if ((difftime(time(nullptr), buff.second->timemark) >= DEF_BUFFFILL_INTERVAL_SEK)
						 && (!buff.second->completed())) {
						 buff.second->timemark = time(nullptr);
						 switch (buff.second->getHeader()->data_type)
						 {
						 case edtBlock:
							 buff.second->getNeedParts(first, count);
							 if (count)
								 net_command_get_entitypart(buff.second->sender.host, buff.second->sender.port,
															buff.second->getHeader()->cmd_data.total_hash, first, count);
							 
							 break;
						 case edtEntityParts:
							 nhash = buff.second->getHeader()->cmd_data.entity_part_data.entity_hash;
							 sprintf(hst, "%s", buff.second->sender.host);
							 prt = buff.second->sender.port;
							 first = buff.second->getHeader()->cmd_data.entity_part_data.offset;
							 count = buff.second->getHeader()->cmd_data.entity_part_data.count;
							 bufs_to_erase.emplace_back(buff.first);
							 
							 //erase_bad_recv_buffer(buff.first);
							 if (count) net_command_get_entitypart(hst, prt, nhash, first, count);
							 break;
						 case edtRestoreChain:
							 if (buff.second->getPart(0))
							 {
								 //(RestoreChainInfo *)buff.second->parts[0].ptr
								 //auto p1 = buff.second->getPart(0);
								 auto p2 = buff.second->getPart(0).get();
								 RestoreChainInfo *p = (RestoreChainInfo *)p2->data;
									//RestoreChainInfo * p = (RestoreChainInfo *)(buff.second->getPart(0).get()->data);
								 nhash = db_singleton.hSync.bottom_hash;
								 sprintf(hst, "%s", buff.second->sender.host);
								 prt = buff.second->sender.port;

								 bufs_to_erase.emplace_back(buff.first);
								 //erase_bad_recv_buffer(buff.first);
								 net_command_get_restorechain(hst, prt, nhash, p->part_num);
							 }
							 else {
								 bufs_to_erase.emplace_back(buff.first);
								 hash_type l = db_singleton.GetLastHash();
								 net_command_get_restorechain(db_singleton.hSync.chainsender, l);
							 }
							 break;
						 default:
							 
							 bufs_to_erase.emplace_back(buff.first);
							 //erase_bad_recv_buffer(buff.first);
							 break;
						 }
					 }
				 }
		 }
		 for (auto er : bufs_to_erase)
			 erase_bad_recv_buffer(er);
	 }
	 catch (const std::exception &e)
	 {
		 logger.exc("on_buftimer: %s", e.what());
	 }
	 evtimer_add(PCtx->bufftimer_event, &buffer_fill_timeout);
	 SendRecvDeques.recv_unlock();
 }
