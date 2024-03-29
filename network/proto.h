#pragma once

#include <stdexcept>
#include <vector>
#include <memory>
#include <mutex>

#include <common/defs.h>
#include <common/macro.h>

#include "common/log.h"
#include "crypto.h"
#include <ed25519.h>

#include <event2/event.h>

//sockaddr_in6
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <netinet/in.h>
#endif

#define MAX_PART_SIZE       0x0400

extern "C" {
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>
}

#include "common/types.h"
#include "hosts.h"

#define LUA     LUA_LOCK lua_lock;

#define LUA_CB_I_AM "ra_callback_i_am"
#define LUA_CB_I_AM_TOO "ra_callback_i_am_too"
#define LUA_CB_HE_IS "ra_callback_he_is"
#define LUA_CB_GET_ENTITY "ra_callback_get_entity"
extern struct timeval buffer_fill_timeout;

enum ProtoCommands : int32_t {
	protoUndefined = -1,
	protoInvalid = protoUndefined,
	protoNoCommand = 0,
	protoSendEntity = protoNoCommand,
	protoIam,
	protoIamtoo,
	protoHeIs,
	protoGetEntity,
	protoLastHash,
	protoGetEntityPart,
	protoGetRoundINFO,
	protoSendRoundINFO,
	protoGetRestoreChain, //запрос цепочки блоков для восстановления

	protoCount
};

enum ENTITY_DATA_TYPE :unsigned short {
	edtBlock = 0,
	edtTransaction,
	edtEntityParts,
	edtRestoreChain, //цепочка хешей блоков для восстановления
	edtFlexible,

	edtCount
};

typedef union  CmdStruct {
	CmdStruct() { ZEROIZE(this);}

	struct {//for protoIam and protoIamtoo
		public_type my_public;
		hash_type chainid_hash;
	} my_data;
	hash_type total_hash;//for protoSendEntity
	hash_type entity_hash;//for protoGetEntity
	struct {//for protoHiIs
		public_type his_public;
		ADDR_TYPE addr_type;
		union {
			sockaddr_in in;
			sockaddr_in6 in6;
		} his_addr;
	} his_data;	
	struct {	//for protoGetEntityPart
		hash_type entity_hash;
		uint16_t offset;
		uint16_t count;
	} entity_part_data;
	CmdStruct &operator=(const CmdStruct &cmd_data) {
		if(&cmd_data != this) {
 			//*this = cmd_data;
			memcpy(this, &cmd_data, sizeof(CmdStruct));
		}
		return *this;
	}
} *PCmdStruct;

typedef struct PACKAGE_HEADER {
	PACKAGE_HEADER();
	PACKAGE_HEADER(size_t l, hash_type &hash, public_type &pub, private_type &priv);
	PACKAGE_HEADER(ProtoCommands cmd,
				   CmdStruct &cmd_data,
				   public_type &pub,
				   private_type &priv,
				   unsigned char *ext_data = nullptr, size_t ext_data_sz = 0);
	sign_type header_signature;
	public_type pubkey;
	struct {
		union {
			unsigned char flags[sizeof(uint32_t)];
			ProtoCommands command;
		};
		ENTITY_DATA_TYPE data_type;
		uint32_t dwsz;
	};
	CmdStruct cmd_data;
	bool valid();
	bool init(size_t l, hash_type &hash, public_type &pub, private_type &priv,ENTITY_DATA_TYPE dt=edtBlock);	
	size_t parts_count() const;
} *HPACKAGE_HEADER, *PPACKAGE_HEADER;

typedef struct PACKAGE_PART_HEADER {
	PACKAGE_PART_HEADER() : N(0), sz(0) {
		ZEROARR(part_hash.data);
		ZEROARR(total_hash.data);
	}
	hash_type part_hash;//hash of header excluding itself and data[sz] after header
	hash_type total_hash;//equal to PACKAGE_HEADER::total_hash
	size_t N;//N < (PACKAGE_HEADER::L >> 0x0A) + (!!(PRED(MAX_PART_SIZE) & PACKAGE_HEADER::L))
	size_t sz;//sz <= MAX_PART_SIZE
} *HPACKAGE_PART_HEADER, *PPACKAGE_PART_HEADER;

enum PP_VALID_ERR {
	ppveUndefined = -1,

	ppveNoError = 0,
	ppveSzError,
	ppveNumberError,
	ppveTotalHashError,
	ppveHashError,

	ppveCount
};

typedef struct PACKAGE_PART {
	PACKAGE_PART() {
		ZEROARR(data);
	}
	PACKAGE_PART_HEADER header;
	unsigned char data[MAX_PART_SIZE];
	bool check_hash() const;
	bool calc_hash();
	PP_VALID_ERR valid(const PACKAGE_HEADER &package_header) const;
} *HPACKAGE_PART, *PPACKAGE_PART;

typedef struct PACKAGE_PART_PTR {
	PACKAGE_PART_HEADER header;
	const unsigned char *ptr;
	bool calc_hash();
	bool valid();
} *HPACKAGE_PART_PTR, *PPACKAGE_PART_PTR;

typedef struct PACKAGE_BUFFER {
public:
	explicit PACKAGE_BUFFER(const PACKAGE_HEADER &init_header);
	PACKAGE_BUFFER(std::shared_ptr<unsigned char> data, size_t data_sz,
				   public_type &pub, private_type &priv,ENTITY_DATA_TYPE data_type=edtBlock);
	~PACKAGE_BUFFER();
	bool appendPart(const unsigned char *data, size_t data_sz);
	bool appendPart(const PACKAGE_PART &part);
	HPACKAGE_HEADER getHeader() {
		return &header;
	}
	std::shared_ptr<PACKAGE_PART> getPart(size_t N);
	std::shared_ptr<unsigned char> getData(size_t &data_sz);
	bool valid();
	bool completed();	
	time_t timemark = 0;
	void getNeedParts(size_t &firstneedpart, size_t &countneedparts);
	struct {
		char host[16]; // TODO: Заменить на uint32_t
		uint32_t port;
	} sender;
private:
	
	PACKAGE_HEADER header;
	std::shared_ptr<unsigned char> buffer;
	std::vector<PACKAGE_PART_PTR> parts;
	bool b_completed;
} *HPACKAGE_BUFFER, *PPACKAGE_BUFFER;

bool parse_package_header(const unsigned char *data,
						  size_t data_sz,
						  hash_type &total_hash,
						  size_t &length,
						  char *Status = nullptr,
						  size_t StatusSz = 0);

bool parse_package_part_header(const PACKAGE_HEADER &package_header,
							   const unsigned char *data,
							   size_t data_sz,
							   hash_type &hash,
							   size_t &sz,
							   size_t &N,
							   char *Status = nullptr,
							   size_t StatusSz = 0);
//Proto Command handle types

typedef bool (*CmdHandler)(CmdStruct &, sockaddr_in &, const char *);
typedef struct {
	CmdHandler handler;
	mutable const char *callback_name;
} CmdDesc;

typedef struct ENTITY_PART {	
	explicit ENTITY_PART(size_t sz, hash_type blockhash) : block(std::move(blockhash)), offsetpartsnumber(0), firstpartnumber(0), data_sz(sz) {}
	~ENTITY_PART() = default;
	hash_type block;
	uint16_t offsetpartsnumber;
	uint16_t firstpartnumber;
	size_t data_sz;
	//unsigned char * data;
	//std::shared_ptr<unsigned char>data;
}*HENTITY_PART;
struct LUA_LOCK;

typedef struct CMD_HANDLERS_POOL {
	friend struct LUA_LOCK;
public:
	typedef struct COMMAND_EMITS {
		typedef bool (*cmd_iam_t)(const char *host,
										const unsigned short port,
										char *Status, size_t StatusSz);
		typedef bool (*cmd_iamtoo_t)(const char *host,
										   const unsigned short port,
										   char *Status, size_t StatusSz);
		typedef bool (*cmd_heis_t)(const char *host,
										 const unsigned short port,
										 public_type &his_pub,
										 const char *his_host,
										 const unsigned short his_port,
										 char *Status, size_t StatusSz);
		typedef bool (*cmd_get_entity_t)(const char *host,
											   const unsigned short port, hash_type &entity_hash,
											   char *Status, const size_t StatusSz);
		typedef bool (*cmd_last_hash_t)(const char *host,
											  const unsigned short port,
											  char *Status, const size_t StatusSz);
		typedef bool (*cmd_get_entitypart_t)(const char *host, unsigned short port, hash_type &entity_hash, uint16_t offset, uint16_t parts_count,
			char *Status, size_t StatusSz);
		cmd_iam_t iam;
		cmd_iamtoo_t iamto;
		cmd_heis_t heis;
		cmd_get_entity_t get_entity;
		cmd_last_hash_t last_hash;
		cmd_get_entitypart_t get_entitypart;
	} *HCOMMAND_EMITS, *PCOMMAND_EMITS;

	CMD_HANDLERS_POOL();
	~CMD_HANDLERS_POOL();
	bool try_command(ProtoCommands cmd, CmdStruct &cmd_data, sockaddr_in &addr);
	bool init_emits(COMMAND_EMITS &emits) {
		hEmits = new COMMAND_EMITS(emits);
		return hEmits;
	}
	const COMMAND_EMITS &emits() { return *hEmits; }
	bool init_lua_src(const char *src);
	lua_State &luaState() { return *Lstate; }
	void test() {
		auto &handler = handlers[1];
		lua_getglobal(Lstate, handler.callback_name);
		logger.dbg("try to call");
		public_type my_public;// = {0};
		lua_pushstring(Lstate, NET_ADDR);
		lua_pushnumber(Lstate, UDP_PORT);
		lua_pushlightuserdata(Lstate, my_public.data);
		auto lua_res = lua_pcall(Lstate,3,1,0);
		logger.dbg("lua_pcall result %d", lua_res);
		auto res = lua_tointeger(Lstate, -1);
		logger.dbg("lua result %d", (CALLBACK_RES)res);
	}
private:
	enum CALLBACK_RES {
		cbresError = -1,
		cbresPass = 0,
		cbresBreak = 1
	};
	std::mutex lua_m;
	static bool proto_handle_Iam(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_Iamtoo(CmdStruct &, sockaddr_in &, const char*);
	static bool proto_handle_HeIs(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_GetEntity(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_LastHash(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_GetRoundINFO(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_SendRoundINFO(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_GetEntityPart(CmdStruct &, sockaddr_in &, const char *);
	static bool proto_handle_GetRestoreChain(CmdStruct &, sockaddr_in &, const char *);
	const CmdDesc handlers[protoCount] = {
			{nullptr, nullptr},
			{proto_handle_Iam, LUA_CB_I_AM},
			{proto_handle_Iamtoo, LUA_CB_I_AM_TOO},
			{proto_handle_HeIs, LUA_CB_HE_IS},
			{proto_handle_GetEntity, LUA_CB_GET_ENTITY},
			{proto_handle_LastHash, nullptr},
			{proto_handle_GetEntityPart,nullptr},
			{proto_handle_GetRoundINFO,nullptr},
			{proto_handle_SendRoundINFO,nullptr},			
			{proto_handle_GetRestoreChain,nullptr}
	};
	HCOMMAND_EMITS hEmits;
	lua_State *Lstate;//For LUA callbacks
} *HCMD_HANDLERS_POOL, *PCMD_HANDLERS_POOL;

extern CMD_HANDLERS_POOL handlers_pool;

typedef struct LUA_LOCK {
	LUA_LOCK() { handlers_pool.lua_m.lock(); }
	~LUA_LOCK() { handlers_pool.lua_m.unlock(); }
} *HLUA_LOCK, *PLUA_LOCK;
//void on_buftimer(evutil_socket_t fd, short kind, void *arg);

