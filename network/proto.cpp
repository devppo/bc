#include "proto.h"
#include "../database/blocks_thread.h"
#include "net.h"

// макс.длина передачи цепочки хешей для восстановления
#define MAX_RESTORECHAIN_LENGTH 20
//void on_buftimer(evutil_socket_t fd, short kind, void *arg);
struct timeval buffer_fill_timeout = { 5,0 }; //TODO time constant
CMD_HANDLERS_POOL handlers_pool;
//------------------------------------------------------------------------------
PACKAGE_HEADER::PACKAGE_HEADER() : command(protoNoCommand), data_type(edtBlock), dwsz(0) {
    ZEROARR(header_signature.data);
    ZEROARR(cmd_data.total_hash.data);
}

PACKAGE_HEADER::PACKAGE_HEADER(size_t _sz, hash_type &hash, public_type &pub, private_type &priv) : command(protoSendEntity), data_type(edtBlock), dwsz(_sz)  {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    memcpy(cmd_data.total_hash.data, hash.data, sizeof(hash_type));
    memcpy(pubkey.data, pub.data, public_type::get_sz());
    if(!sign(pubkey.data,
                c_signed_sz,
                pub.data,
                public_type::get_sz(),
                priv.data,
                private_type::get_sz(),
                header_signature.data,
                sign_type::get_sz()))

    {
        throw std::runtime_error("Package header: sign failure");
    }
}

PACKAGE_HEADER::PACKAGE_HEADER(ProtoCommands cmd,
        CmdStruct &_cmd_data,
        public_type &pub,
        private_type &priv,
        unsigned char *ext_data,
        size_t ext_data_sz) : command(cmd), dwsz(ext_data_sz)
{
    switch(command) {
    	case protoIamtoo:
        case protoIam:
        {
            if(dwsz)
                throw std::runtime_error("Package header: invalid length");
            if(pub != _cmd_data.my_data.my_public)
                throw std::runtime_error("Package header: public keys mismatch");
            cmd_data = _cmd_data;
            break;
        }
        case protoHeIs:
        case protoGetEntity:
		case protoLastHash:
		case protoGetRoundINFO:
		case protoSendRoundINFO:		
		case protoGetEntityPart:
		case protoGetRestoreChain:
		{
			if (dwsz)
				throw std::runtime_error("Package header: invalid length");
			cmd_data = _cmd_data;
			break;
		}
		default:
            throw std::runtime_error("Package header: invalid command");
    }
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    pubkey = pub;
    if(!sign(pubkey.data,
             c_signed_sz,
             pub.data,
             public_type::get_sz(),
             priv.data,
             private_type::get_sz(),
             header_signature.data,
             sign_type::get_sz()))

    {
        throw std::runtime_error("Package header: sign failure");
    }
}

bool PACKAGE_HEADER::valid() {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    switch(command)
    {
        case protoSendEntity:
        {
            if(!dwsz) {
                logger.err("Data buffer is empty for PACKAGE_HEADER command %d", command);
                return false;
            }
            break;
        }
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
            if(dwsz) {
                logger.err("Data buffer is not empty for PACKAGE_HEADER command %d", command);
                return false;
            }
            break;
        }
        default:
            logger.err("Unknown PACKAGE_HEADER command %d", command);
            return false;
    }
    if(!verify(pubkey.data,
            c_signed_sz,
            pubkey.data,
            public_type::get_sz(),
            header_signature.data,
            sign_type::get_sz()))
    {
        logger.err("PACKAGE_HEADER signature mismatch");
        return false;
    }
    return true;
}

bool PACKAGE_HEADER::init(size_t _sz, hash_type &hash, public_type &pub, private_type &priv,ENTITY_DATA_TYPE dt) {
    const size_t c_signed_sz = sizeof(PACKAGE_HEADER) - FIELD_OFFS(PACKAGE_HEADER, pubkey);
    dwsz = _sz;
    command = protoSendEntity;
    cmd_data.total_hash = hash;
    pubkey = pub;
	data_type = dt;
    return sign(pubkey.data,
            c_signed_sz,
            pub.data,
            public_type::get_sz(),
            priv.data,
            private_type::get_sz(),
            header_signature.data,
            sign_type::get_sz());
}

size_t PACKAGE_HEADER::parts_count() const {
    //return (dwsz / MAX_PART_SIZE) + (dwsz % MAX_PART_SIZE != 0);
    return (dwsz >> 0x0A) + ((PRED(MAX_PART_SIZE) & dwsz) != 0);
}
//------------------------------------------------------------------------------
bool PACKAGE_PART::check_hash() const {
    const size_t c_hashed_sz = sizeof(PACKAGE_PART_HEADER) -
            FIELD_OFFS(PACKAGE_PART_HEADER, total_hash) +
            header.sz;
    hash_type hash;
    if(blake2(hash.data, sizeof(hash_type), &header.total_hash, c_hashed_sz, nullptr, 0) < 0) {
        return false;
    }
    return header.part_hash == hash;
}

bool PACKAGE_PART::calc_hash() {
    const size_t c_hashed_sz = sizeof(PACKAGE_PART_HEADER) -
                               FIELD_OFFS(PACKAGE_PART_HEADER, total_hash) +
                               header.sz;
    if(blake2(header.part_hash.data, sizeof(hash_type), &header.total_hash, c_hashed_sz, nullptr, 0) < 0) {
        return false;
    }
    return true;
}

PP_VALID_ERR PACKAGE_PART::valid(const PACKAGE_HEADER &package_header) const {
    if(header.sz > MAX_PART_SIZE) {
        return ppveSzError;
    }
    if(package_header.parts_count() <= header.N) {
        return ppveNumberError;
    }
    if(package_header.cmd_data.total_hash !=
            header.total_hash)
    {
        return ppveTotalHashError;
    }
    if(!check_hash()) {
        return ppveHashError;
    }
    return ppveNoError;
}
//------------------------------------------------------------------------------
bool PACKAGE_PART_PTR::calc_hash() {
    const size_t c_header_hashed_sz =
            sizeof(PACKAGE_PART_HEADER) -
            FIELD_OFFS(PACKAGE_PART_HEADER, total_hash);
    blake2b_state S[1];
    if( blake2b_init( S, sizeof(header.part_hash) ) < 0 ) return false;
    blake2b_update( S, &header.total_hash, c_header_hashed_sz );
    blake2b_update( S, ptr, header.sz );
    blake2b_final( S, header.part_hash.data, sizeof(header.part_hash));
    return true;
}

bool PACKAGE_PART_PTR::valid() {
    if(!ptr) return false;
    hash_type hash;
    const size_t c_header_hashed_sz =
            sizeof(PACKAGE_PART_HEADER) -
            FIELD_OFFS(PACKAGE_PART_HEADER, total_hash);
    blake2b_state S[1];
    if( blake2b_init( S, sizeof(hash) ) < 0 ) return false;
    blake2b_update( S, &header.total_hash, c_header_hashed_sz );
    blake2b_update( S, ptr, header.sz );
    blake2b_final( S, hash.data, sizeof(header.part_hash));
    return (hash == header.part_hash);
}
//------------------------------------------------------------------------------
PACKAGE_BUFFER::PACKAGE_BUFFER(const PACKAGE_HEADER &init_header) : sender{'\0',0},
        header(init_header),
        buffer(new unsigned char[init_header.dwsz],
    	std::default_delete<unsigned char[]>()),
        b_completed(false)
{
    parts.resize(header.parts_count());
}

PACKAGE_BUFFER::PACKAGE_BUFFER(std::shared_ptr<unsigned char> data,
        size_t data_sz,
        public_type &pub,
        private_type &priv,ENTITY_DATA_TYPE data_type) : sender{'-',0},
        buffer(data),
        b_completed(false)
{
    hash_type total_hash;
    if(blake2(total_hash.data,
            sizeof(hash_type),
            data.get(),
            data_sz,
            nullptr,
            0) < 0)
    {
        throw std::runtime_error("Package buffer: hash failure");
    }
    if(!header.init(data_sz, total_hash, pub, priv,data_type)) {
        throw std::runtime_error("Package header: hash failure");
    }

    const size_t c_parts_count = header.parts_count();
    parts.resize(c_parts_count);
    for(size_t i = 0; i < c_parts_count; ++i) {
        auto &Ptr = parts[i];
        Ptr.ptr = data.get() + i * MAX_PART_SIZE;
        Ptr.header.total_hash = total_hash;
        Ptr.header.N = i;
        if(i == PRED(c_parts_count)) {
            Ptr.header.sz = data_sz & PRED(MAX_PART_SIZE);//data_sz % MAX_PART_SIZE;
            if(!Ptr.header.sz) Ptr.header.sz = MAX_PART_SIZE;
        } else {
            Ptr.header.sz = MAX_PART_SIZE;
        }
        if(!Ptr.calc_hash()) {
            parts.resize(0);
            throw std::runtime_error("Part hash failure");
        } else {
            PACKAGE_PART part;
            memcpy(part.data, Ptr.ptr, Ptr.header.sz);
            part.header = Ptr.header;
            part.calc_hash();
        }
		timemark = time(nullptr);
    }
}

PACKAGE_BUFFER::~PACKAGE_BUFFER() {
	
}


std::shared_ptr<PACKAGE_PART> PACKAGE_BUFFER::getPart(size_t N) {
    if(N >= header.parts_count())
        return nullptr;
    auto &part_ptr = parts[N];
    if(!part_ptr.valid()) {
        return nullptr;
    }
    if(part_ptr.header.total_hash != header.cmd_data.total_hash) {
        return nullptr;
    }
	std::shared_ptr<PACKAGE_PART> ppart(new PACKAGE_PART());
    ppart.get()->header = part_ptr.header;
    memcpy(ppart.get()->data, part_ptr.ptr, part_ptr.header.sz);
    return ppart;
}

bool PACKAGE_BUFFER::appendPart(const unsigned char *data, size_t data_sz) {
    if(!data) return false;
    if(data_sz < sizeof(PACKAGE_PART)) return false;
    if(!valid()) return false;

    auto hPackagePart = (HPACKAGE_PART)data;
    if(hPackagePart->valid(header) != ppveNoError) return false;
    const size_t c_N = hPackagePart->header.N;
    const size_t c_sz = hPackagePart->header.sz;

    auto &part_ptr = parts[c_N];
    //TODO: check for already filled
    unsigned char *ptr = &buffer.get()[c_N * MAX_PART_SIZE];
    part_ptr.ptr = ptr;
    part_ptr.header.N = c_N;
    part_ptr.header.sz = c_sz;
    part_ptr.header.total_hash = header.cmd_data.total_hash;
    part_ptr.header.part_hash = hPackagePart->header.part_hash;
    memcpy(ptr, hPackagePart->data, c_sz);
	/*if (timer_event !=nullptr)
	{
		if (event_pending(this->timer_event, EV_TIMEOUT, NULL))
			if (!event_del(this->timer_event)) event_add(this->timer_event, &buffer_fill_timeout);
	}*/
    return true;
}

bool PACKAGE_BUFFER::appendPart(const PACKAGE_PART &part) {
    if(!valid()) {
        return false;
    }
    PP_VALID_ERR ppve = part.valid(header);
    if(ppve != ppveNoError) {
        return false;
    }
    const size_t c_N =
            part.header.N;
    const size_t c_sz =
            part.header.sz;

    auto &part_ptr = parts[c_N];
    //TODO: check for already filled
    unsigned char *ptr = &buffer.get()[c_N * MAX_PART_SIZE];
    part_ptr.ptr = ptr;
    part_ptr.header.N = c_N;
    part_ptr.header.sz = c_sz;
    part_ptr.header.total_hash = header.cmd_data.total_hash;
    part_ptr.header.part_hash = part.header.part_hash;
    memcpy(ptr, part.data, c_sz);
	timemark = time(nullptr);
	//if (c_N == 0)
	//	this->timer_event = add_buftimer(buffer_fill_timeout, this);
	//else {
		/*if (timer_event != nullptr)
		{
			if (event_pending(this->timer_event, EV_TIMEOUT, NULL))
				if (!event_del(this->timer_event)) event_add(this->timer_event, &buffer_fill_timeout);
		}*/
	//}
    return true;
}

bool PACKAGE_BUFFER::valid() {
    if(buffer == nullptr) return false;
    if(!header.valid()) {
        return false;
    }
    const size_t c_parts_count = header.parts_count();
    if(c_parts_count != parts.size()) {
        return false;
    }
    for(size_t i = 0; i < c_parts_count; ++i) {
        auto part = parts[i];
        if(((i > 0) && (!part.header.N)) || (!part.ptr)) continue;//Incompleted
        if(part.header.N != i) {
            return false;//Check for index
        }
        if(part.ptr != &buffer.get()[i * MAX_PART_SIZE]) {
            return false;//Check for pointer
        }
        if((i != PRED(c_parts_count)) && (part.header.sz != MAX_PART_SIZE)) {
            return false;
        }
        if(!part.valid()) {
            return false;//Check for hash
        }
    }
    return true;
}

bool PACKAGE_BUFFER::completed() {
if(b_completed) {
        return true;
    }
    //logger.dbg("PACKAGE_BUFFER::completed");
    //for(size_t i = 0; i < parts.size(); ++i) {
    for(auto &part : parts) {
        //auto &part = parts[i];
        //if((i > 0) && (!part.header.N)) return false;
		if (!part.ptr) {
			//if (timer_event == nullptr)
			//	timer_event = add_buftimer(buffer_fill_timeout, this);
			return false;
		}
    }
    b_completed = true;
	
    return true;
}

std::shared_ptr<unsigned char> PACKAGE_BUFFER::getData(size_t &data_sz) {
    if(!valid()) {
        logger.err("PACKAGE_BUFFER::getData: buffer invalid");
        data_sz = 0;
        return nullptr;
    }
    if(!completed()) {
        logger.warn("PACKAGE_BUFFER::getData: buffer incompleted");
        data_sz = 0;
        return nullptr;
    }
    data_sz = header.dwsz;
    return buffer;
}
void PACKAGE_BUFFER::getNeedParts(size_t &firstneedpart,  size_t &countneedparts) {
	firstneedpart = -1;
	countneedparts = 0;
	for (size_t i = 0; i < this->getHeader()->parts_count(); i++) {
		if (parts[i].ptr == nullptr) {
			if (firstneedpart == -1) firstneedpart = i;
			countneedparts++;
		}
		else {
			if (firstneedpart != -1)
				break;
		}
	}
}


//------------------------------------------------------------------------------
bool parse_package_header(const unsigned char *data,
        const size_t data_sz,
        hash_type &total_hash,
        size_t &length,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    ZEROIZE(&total_hash);
    length = 0;

    CHECK_SZ_LESS(data_sz, sizeof(PACKAGE_HEADER), "Data")
    CHECK_NULL("Data", data)

    auto hPackageHeader = (HPACKAGE_HEADER)data;
    if(hPackageHeader->valid()) {
        length = hPackageHeader->dwsz;
        total_hash = hPackageHeader->cmd_data.total_hash;
        SPRINTF(Status,
                length ? "Data contains valid header" :
                "Data contains valid header, package is empty");
        return true;
    } else {
        SPRINTF(Status, "Hash inconsistency");
        return false;
    }
}

bool parse_package_part_header(const PACKAGE_HEADER &package_header,
        const unsigned char *data,
        const size_t data_sz,
        hash_type &hash,
        size_t &sz,
        size_t &N,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    CHECK_SZ_LESS(data_sz, sizeof(PACKAGE_PART), "Data")
    CHECK_NULL("Data", data)

    ZEROARR(hash.data);
    sz = 0;
    N = 0;

    auto hPackagePart = (HPACKAGE_PART)data;
    PP_VALID_ERR ppve = hPackagePart->valid(package_header);
    switch(ppve)
    {
        case ppveNoError:
        {
            hash = hPackagePart->header.part_hash;
            sz = hPackagePart->header.sz;
            N = hPackagePart->header.N;
            SPRINTF(Status, "Found package part %zu of %zu", hPackagePart->header.N, package_header.parts_count());
            return true;
        }
        case ppveSzError:
        {
            SPRINTF(Status, "Invalid part size");
            break;
        }
        case ppveNumberError:
        {
            SPRINTF(Status,
                    "Wrong part number %zu of %zu",
                    hPackagePart->header.N, package_header.parts_count());
            break;
        }
        case ppveTotalHashError:
        {
            SPRINTF(Status, "Total hash mismatch");
            break;
        }
        case ppveHashError:
        {
            SPRINTF(Status, "Hash inconsistency");
            break;
        }
        default:
        {
            SPRINTF(Status, INTERNAL_ERR, (int)ppve);
            break;
        }
    }
    return false;
}
//------------------------------------------------------------------------------
bool CMD_HANDLERS_POOL::proto_handle_Iam(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    logger.log("proto_handle_Iam");
	char his_host[16] = { '\0' };
	sprintf(his_host, "%s", inet_ntoa(addr.sin_addr));
    //const char *his_host = inet_ntoa(addr.sin_addr);
    const unsigned short his_port = ntohs(addr.sin_port);
	hash_type my_id_hach = hash_type();
	if (db_singleton.getChainIdHash(&my_id_hach)) {
		// если хеш от другой цепочки - никаких действий не производится
		if (my_id_hach != cmd_data.my_data.chainid_hash && (!cmd_data.my_data.chainid_hash.empty())) return true;
	}
	bool cb_result = true;
    if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);

        // Если в lua прокинут callback -- выполнится его запуск
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, his_host);
            lua_pushnumber(l, his_port);
            lua_pushlightuserdata(l, cmd_data.my_data.my_public.data);
            auto lua_res = lua_pcall(l,3,1,0);
            if(lua_res != LUA_OK) {
                logger.err("'I am': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                    case cbresError:
                        logger.err("'I am': Lua callback error");
                        cb_result = false;
                        break;
                    case cbresPass:
                        break;
                    case cbresBreak:
                    	cb_result = true;
                    	break;
                    default:
                        logger.err("'I am': Unknown lua callback result %d", res);
                        cb_result = false;
                        break;
                }
            }
        }
    }
    const size_t c_hosts_count = hosts.getHostsCount();
    if(!c_hosts_count) {
        logger.log("There is no hosts to notify about %s:%d", his_host, his_port);
    }
    auto self_sin = get_self_sin();
    // Для каждого принятого пакета iam отправляем пакет he is по всему списку хостов
    // Кроме случая, когда
    for(size_t i = 0; i < c_hosts_count; ++i) {
        sockaddr_in cur_addr;
        ZEROIZE(&cur_addr);
        ADDR_TYPE addr_type = atUnknown;
        public_type pub;
        // берем очередной хост
        if(hosts.getHost(i, cur_addr, pub, addr_type)) {

        	// проверяем совпадение по адресу (отбрасываем себя)
			// TODO: выбрать один из двух вариантов
			//if (!(cur_addr.sin_addr.s_addr == DEF_ADDR && EASYPORT(cur_addr) == UDP_PORT)) { //временно

            if(!(
            		(self_sin.sin_addr.s_addr == cur_addr.sin_addr.s_addr) &&
            		(self_sin.sin_port == cur_addr.sin_port)
            		)) {
                char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
                char cur_host[16];
                sprintf(cur_host, "%s", inet_ntoa(cur_addr.sin_addr));
                //const char *cur_host = inet_ntoa(cur_addr.sin_addr);
                const unsigned short cur_port = ntohs(cur_addr.sin_port);
                if(handlers_pool.hEmits->heis(cur_host,
                        cur_port,
                        cmd_data.my_data.my_public,
                        inet_ntoa(addr.sin_addr),
                        ntohs(addr.sin_port),
                        Status,
                        COUNT(Status)))
                {
                    cb_result = true;
                    logger.log("Authentic data of %s:%d sent to %s:%d",
                            his_host, his_port, cur_host, cur_port);
                } else {
                    logger.err("proto_handle_Iam 'He is' send error %s", Status);
                }
            }

        }
    }
	// хост-отправитель iam команды добавляется в список хостов
	db_singleton.insert_host(his_host, his_port, cmd_data.my_data.my_public);
	net_command_iamtoo(addr);
	//net_command_iamtoo(inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	// если определен пишущий узел раунда, хост-отправитель извещается о нем
	//sockaddr_in roundaddr{};
	if (hosts.getMainHost())
		net_command_sendroundinfo(addr);
		//net_command_sendroundinfo(inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	return cb_result;
}

bool CMD_HANDLERS_POOL::proto_handle_Iamtoo(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	logger.log("proto_handle_Iamtoo");
	const char *his_host = inet_ntoa(addr.sin_addr);
	const unsigned short his_port = ntohs(addr.sin_port);
	// TODO: Iamtoo callback
	//bool result = false;
	db_singleton.insert_host(his_host, his_port, cmd_data.my_data.my_public);
	return true;
}

bool CMD_HANDLERS_POOL::proto_handle_HeIs(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	logger.log("proto_handle_HeIs");
	char his_host[16] = { '\0' };
	sprintf(his_host, "%s", inet_ntoa(addr.sin_addr));
	bool cb_result = true;
	if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, inet_ntoa(addr.sin_addr));
            lua_pushnumber(l, htons(addr.sin_port));
            lua_pushstring(l, inet_ntoa(cmd_data.his_data.his_addr.in.sin_addr));
            lua_pushnumber(l, htons(cmd_data.his_data.his_addr.in.sin_port));
            lua_pushlightuserdata(l, cmd_data.his_data.his_public.data);
            auto lua_res = lua_pcall(l,5,1,0);
            if(lua_res != LUA_OK) {
                logger.err("'He is': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                    case cbresError:
                        logger.err("'He is': Lua callback error");
                        cb_result = false;
                        break;
                    case cbresPass:
                        break;
                    case cbresBreak:
                    	cb_result = true;
                    	break;
                    default:
                        logger.err("'He is': Unknown lua callback result %d", res);
                        cb_result = false;
                        break;
                }
            }
        }
    }

    Host host{cmd_data.his_data.his_addr.in, ADDR_TYPE::atUnknown};
	public_type key;
	if(hosts.getHost(key, host.address, host.addr_type)) {
		;
	}
	else {
		db_singleton.insert_host(inet_ntoa(host.address.sin_addr), ntohs(host.address.sin_port), cmd_data.my_data.my_public);
		net_command_iamtoo(inet_ntoa(host.address.sin_addr), ntohs(host.address.sin_port));
	}

    return cb_result;
}

bool CMD_HANDLERS_POOL::proto_handle_GetEntity(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
    if(lua_callback_name) {
        LUA

        lua_State *l = handlers_pool.Lstate;
        lua_settop (l, 0);
        lua_getglobal(l, lua_callback_name);
        if ( lua_isnil(l,-1) ) {
            lua_settop(l, 0);
        } else {
            lua_pushstring(l, inet_ntoa(addr.sin_addr));
            lua_pushnumber(l, ntohs(addr.sin_port));
            lua_pushlightuserdata(l, cmd_data.entity_hash.data);
            auto lua_res = lua_pcall(l,3,1,0); 
            if(lua_res != LUA_OK) {
                logger.err("'Get Entity': LUA error: %s", lua_tostring(l, -1));
            } else {
                const auto res = (CALLBACK_RES) lua_tointeger(l, -1);
                lua_settop(l, 0);
                switch (res) {
                    case cbresError:
                        logger.err("'Get Entity': Lua callback error");
                        return false;
                    case cbresPass:
                        break;
                    case cbresBreak:
                        return true;
                    default:
                        logger.err("'Get Entity': Unknown lua callback result %d", res);
                        return false;
                }
            }
        }
    }
    return true;
}

bool CMD_HANDLERS_POOL::proto_handle_LastHash(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	//if (db_singleton.hSync.SyncState() ==SyncHandler::eSyncLanch)
	//	if (EASYPORT(db_singleton.hSync->syncaddr)==EASYPORT(addr) && db_singleton.hSync->syncaddr.sin_addr.s_addr==addr.sin_addr.s_addr)		
	//		return true; // если запущена синхронизация и адреса совпадают - никаких действий не производится
	//TODO: (??) действия callback НЕ ДОЛЖНЫ (или ДОЛЖНЫ??) перекрывать действия кода:: перенести вызов callback ниже	
	bool cb_result = true;
	if (lua_callback_name) {
		LUA

			lua_State *l = handlers_pool.Lstate;
		lua_settop(l, 0);
		lua_getglobal(l, lua_callback_name);
		if (lua_isnil(l, -1)) {
			lua_settop(l, 0);
		}
		else {
			lua_pushstring(l, inet_ntoa(addr.sin_addr));
			lua_pushnumber(l, htons(addr.sin_port));
			lua_pushlightuserdata(l, cmd_data.entity_hash.data);
			auto lua_res = lua_pcall(l, 3, 1, 0);
			if (lua_res != LUA_OK) {
				logger.err("'Last Hash': LUA error: %s", lua_tostring(l, -1));
			}
			else {
				const auto res = (CALLBACK_RES)lua_tointeger(l, -1);
				lua_settop(l, 0);
				switch (res) {
				case cbresError:
					logger.err("'Last Hash': Lua callback error");
					cb_result= false;
				case cbresPass:
					break;
				case cbresBreak:
					cb_result= true;
					break;
				default:
					logger.err("'Last Hash': Unknown lua callback result %d", res);
					cb_result= false;
				}
			}
		}
	}
	hash_type mylasthash = db_singleton.GetLastHash();
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	if (mylasthash != cmd_data.total_hash  ) {
		if (db_singleton.hashExists(cmd_data.total_hash,true) || cmd_data.total_hash.empty()) {		
			if (handlers_pool.hEmits->last_hash(EASYHOST(addr),ntohs(addr.sin_port) , Status, COUNT(Status))) {
				logger.dbg("Last hash HANDLE: been generate 'Last hash' command to %s:%d", EASYHOST(addr), EASYPORT(addr));
			}
			else {
				logger.dbg("Last hash HANDLE: generation 'Last hash' command to %s:%d FAILED", EASYHOST(addr), EASYPORT(addr));
			}

		}
		else {
			//!! флаг начала синхронизации взводится здесь 
			//TODO: вместо этого - вызов protoGetResoreChain
			logger.dbg("Last hash HANDLE: syncronization requered!");
			db_singleton.hSync.chainsender = addr;
			net_command_get_restorechain(inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), mylasthash);
		}		
	}
	else {
		// TODO: send sync ok message
		logger.dbg("Last hash HANDLE: nothing do, hashes equal width %s:%d", EASYHOST(addr), EASYPORT(addr));
	}
	return cb_result;
}

bool CMD_HANDLERS_POOL::proto_handle_GetRoundINFO(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	
	if (lua_callback_name) {
		//TODO: каллбэк для этой команды пока не определен
	}
	auto hst = inet_ntoa(addr.sin_addr);
	
	return net_command_sendroundinfo(hst, addr.sin_port);
}
bool CMD_HANDLERS_POOL::proto_handle_SendRoundINFO(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	return hosts.setMainHost(cmd_data.his_data.his_addr.in);	
}
bool CMD_HANDLERS_POOL::proto_handle_GetEntityPart(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	if (lua_callback_name) {
		//TODO: каллбэк для этой команды пока не определен
	}
	/*result, db_block, db_block_sz, status = db_obtain(handler, hash, hash_sz)
		if result then
			result, status = net_sendto(db_block, db_block_sz, host, port)
			end*/
	unsigned char *db_data = nullptr;
	size_t db_data_sz = 0;
	if (!db_singleton.interlocked_obtain((unsigned char *)&cmd_data.entity_part_data.entity_hash,hash_type::get_sz(),
		db_data,db_data_sz))
			return false;
	/*auto block_offset = (cmd_data.entity_part_data.offset ) * MAX_PART_SIZE;
	if (block_offset >= db_data_sz)
		return false;*/
	//auto send_data_sz = block_offset + (cmd_data.entity_part_data.count * MAX_PART_SIZE) > db_data_sz ? db_data_sz - block_offset : cmd_data.entity_part_data.count * MAX_PART_SIZE;
	//unsigned char *send_data = (db_data + block_offset);
	auto hst = inet_ntoa(addr.sin_addr);
	ENTITY_PART entity_data(db_data_sz, cmd_data.entity_part_data.entity_hash);
	//entity_data.block = cmd_data.entity_part_data.entity_hash;
	entity_data.firstpartnumber = cmd_data.entity_part_data.offset;
	entity_data.offsetpartsnumber = cmd_data.entity_part_data.count;
	//ra_command_send_entitypart(cmd_data, addr);
	return net_sendto(hst, ntohs(addr.sin_port), (unsigned char *) &entity_data, sizeof(ENTITY_PART),
					  ENTITY_DATA_TYPE::edtEntityParts);
}
bool CMD_HANDLERS_POOL::proto_handle_GetRestoreChain(CmdStruct &cmd_data, sockaddr_in &addr, const char *lua_callback_name) {
	//ENTITY_DATA_TYPE::edtRestoreChain
	bool retcode = true;
	auto hst = inet_ntoa(addr.sin_addr);
	hash_type first = cmd_data.entity_part_data.entity_hash;
	int part = -1;
	if (cmd_data.entity_part_data.count != 0)
		part = cmd_data.entity_part_data.offset;
	std::vector<RestoreChainItem> lst = db_singleton.get_chainhashes(first);
	size_t total_sz = lst.size();
	size_t total_parts = (total_sz / MAX_RESTORECHAIN_LENGTH) + (total_sz % MAX_RESTORECHAIN_LENGTH > 0 ? 1 : 0);
	size_t l = total_sz;
	size_t curr_part = 0;
	if (l)
	{
		hash_type last = db_singleton.GetLastHash();
		size_t gl_i = 0;
		while (l>0)
		{
			size_t c_sz = (l > MAX_RESTORECHAIN_LENGTH ? MAX_RESTORECHAIN_LENGTH : l);
			size_t byte_sz = sizeof(RestoreChainInfo) + (sizeof(RestoreChainItem) * c_sz);
			l -= (MAX_RESTORECHAIN_LENGTH > l) ? l : MAX_RESTORECHAIN_LENGTH;
			unsigned char *buff = new unsigned char[byte_sz];
			//
			RestoreChainInfo * data_tosend = (RestoreChainInfo *)buff;
			data_tosend->final_hash = last;
			data_tosend->sender = get_self_sin();
			data_tosend->sz = c_sz;
			data_tosend->part_num = curr_part++;
			data_tosend->total_parts = total_parts;
			data_tosend->total_sz = total_sz;
			//int i = 0;
			for (size_t i = 0; i < c_sz; i++) {
				auto itm = lst[gl_i++];
				/*hash_type t;
				t.from_hex(itm.c_str());*/
				memcpy((char *)&(data_tosend->chain[i]), (char *)&itm, sizeof(RestoreChainItem));
			}
			if (part==-1 || data_tosend->part_num==part)
				retcode &= net_sendto(hst, ntohs(addr.sin_port), buff, byte_sz, ENTITY_DATA_TYPE::edtRestoreChain);
			delete[] buff;
			std::this_thread::sleep_for(std::chrono::milliseconds(50));
		}
		return retcode;
	}
	else
		return false;
}


//------------------------------------------------------------------------------
CMD_HANDLERS_POOL::CMD_HANDLERS_POOL() : hEmits(nullptr), Lstate(luaL_newstate()) {
    if(Lstate) {
        logger.log("LUA initialized");
        //Common libraries load for new LUA state instance
        luaL_openlibs(Lstate);
    } else {
        logger.err("LUA initialization failure");
    }
}

CMD_HANDLERS_POOL::~CMD_HANDLERS_POOL() {
    delete hEmits;
    if(Lstate) {
        lua_close(Lstate);
        logger.log("LUA deinitialized");
    }
}

bool CMD_HANDLERS_POOL::init_lua_src(const char *src) {
    logger.dbg("luaL_dofile loads %s", src);
    int res = luaL_dofile(Lstate, src);
    if(res) logger.err( "Error loading %s: %s", src, luaL_checkstring (Lstate, -1) );
    bool result = res == LUA_OK;
    logger.dbg("luaL_dofile result: %d", res);
    for(auto &handler : handlers) {
        if(handler.handler && handler.callback_name) {
            lua_getglobal(Lstate, handler.callback_name);
            if(lua_isnil(Lstate,-1)) {
                logger.log("LUA callback %s not found", handler.callback_name);
                handler.callback_name = nullptr;
            } else {
                logger.log("LUA callback %s found", handler.callback_name);
            }
            lua_settop(Lstate, 0);//?
        }
    }
    return result;
}

bool CMD_HANDLERS_POOL::try_command(ProtoCommands cmd, CmdStruct &cmd_data, sockaddr_in &addr) {
    if(cmd < protoNoCommand) return false;
    if(cmd >= protoCount) return false;
    const CmdDesc &Desc = handlers[cmd];
    CmdHandler handler = Desc.handler;
    if(!handler) return false;
    return handler(cmd_data, addr, Desc.callback_name);
}
//------------------------------------------------------------------------------

