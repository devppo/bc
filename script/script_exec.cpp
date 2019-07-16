#include <map>
#include <string>
#include <fstream>
#include "script_exec.h"
#include "../database/blocks_thread.h"
#include "../network/proto.h"
#include "../network/net.h"

const int c_cmd_deinit_hosts_args = 1;

typedef struct {
    std::map<std::string,int> values ;
} sHosts;

//------------------------------------------------------------------------------
#define LUA_CALL(call, calltitle)         if((call) != LUA_OK) { \
    SPRINTF(Status, \
            "LUA script error: %s: %s\n", \
            calltitle, \
            lua_tostring(state, -1)); \
    lua_pop(state, 1); \
    lua_close(state); \
    return false; \
}
//------------------------------------------------------------------------------
/*
 * LUA common functionsy
 */
#ifdef __cplusplus
extern "C"
#endif
int lua_msleep(lua_State *state) {
	int m = static_cast<int> (luaL_checknumber(state, 1));
	std::this_thread::sleep_for(std::chrono::microseconds(m * 1000));
	return 0;
}



#ifdef __cplusplus
extern "C"
#endif
int lua_init_hosts(lua_State* state){
    try {
        auto _hosts = new Hosts();
        lua_pushboolean(state, 1);
        lua_pushlightuserdata(state,_hosts);
    }
    catch (...) {
        lua_pushboolean(state, 0);
        lua_pushnil(state);
        return 1;
    }
    return 2;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_deinit_hosts(lua_State* state){
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_cmd_deinit_hosts_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "init_database() was called with %d arguments, %d arguments required",
                args, c_cmd_deinit_hosts_args);
    }
    else {
        if (auto _hosts = (Hosts *) lua_touserdata(state, 1)) {
            lua_pushboolean(state, 1);
            delete _hosts;
        } else {
            lua_pushboolean(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
//args = handler,hosts,file
int lua_read_hosts(lua_State *state) {
	// TODO: return status
	sockaddr_in ip_addr{};
	//char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
	int args = lua_gettop(state);
    if(args != 3){
        return 1;
    }

    if(auto handler = (DbHandler*)lua_touserdata(state,1)){
		if(auto _hosts = (sHosts*)lua_touserdata(state,2)){
            char* file_path = (char*)lua_tostring(state,3);			
            auto& h = _hosts->values;
            std::ifstream file(file_path);
            std::string line;
            if (!file.is_open()) {
                lua_pushboolean(state, 0);
				logger.err("Not open file %s", file_path);
            }
			else {
				while (std::getline(file, line)) {
					size_t full_size = line.size();
					size_t sep = line.find(':');
					if (line.find('#') != std::string::npos) {
						//logger.dbg("HOSTS.TXT comment: %s", line.c_str());
						//continue;
					}
					else {
						if (sep != std::string::npos)
						{
							std::string ip = line.substr(0, sep);
							int port = std::stoi(line.substr(sep + 1, full_size));
							if (!strcmp(ip.c_str(), NET_ADDR) && port == UDP_PORT) {
								//skip
							}
							else {
								h.insert(std::make_pair(ip, port));
								// old:
								//handler->insert_host(ip.c_str(), port, public_type());

								ip_addr.sin_family = AF_INET;
								ip_addr.sin_port = htons(port);
								ip_addr.sin_addr.s_addr = inet_addr(ip.c_str());
								hosts.appendHost(public_type(), ip_addr, ADDR_TYPE::atUnknown);
							}
						}
					}
				}
				lua_pushboolean(state, 1);
			}

            
        }
        else {
            //error
        }
		handler->update_hosts();
		if (SetMainOnRun_FLG)
		{
			ip_addr.sin_family = AF_INET;
			ip_addr.sin_addr.s_addr = inet_addr(NET_ADDR);
			ip_addr.sin_port = htons(UDP_PORT);
			//hosts.appendHost(db_singleton.getDbPublicKey(), ip_addr, ADDR_TYPE::atUnknown);
			hosts.setMainHost(ip_addr);
		}
		
    }
    else {
        //Error

        lua_pushboolean(state, 0);
    }

	return 3;
}

//------------------------------------------------------------------------------
/*
 * LUA-wrappers for memory access
 */
#ifdef __cplusplus
extern "C"
#endif
int lua_hostalloc(lua_State* state) {
    int args = lua_gettop(state);
    if(args == 1) {
        auto sz = (size_t)lua_tonumber(state, 1);
        if(sz) {
            try {
                auto result = new unsigned char[sz];
                lua_pushlightuserdata(state, result);
            } catch(...) {
                lua_pushnil(state);
            }
        } else {
            lua_pushnil(state);
        }
    }
    return 1;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_hostfree(lua_State *state) {
    int args = lua_gettop(state);
    if (args == 1) {
        auto arg = (unsigned char *)lua_touserdata(state, 1);
        if(arg) {
            try {
                delete[] arg;
            } catch(...) {
                return ~0;
            }
        } else {
            return ~0;
        }
    }
    return 0;
}
//Reading raw memory
#ifdef __cplusplus
extern "C"
#endif
int lua_hostread(lua_State *state) {
    logger.dbg("lua_hostread");
    int args = lua_gettop(state);
    if(args == 2) {
        auto mem = (char *)lua_touserdata(state, 1);
        auto sz = (size_t)lua_tonumber(state, 2);
        lua_pushlstring(state, mem, sz);
    }
    return 1;
}
//------------------------------------------------------------------------------
#ifdef __cplusplus
extern "C"
#endif
int lua_hostsleep(lua_State *state) {
    int args = lua_gettop(state);
    if(args == 1) {
        auto sec = (unsigned int)lua_tonumber(state, 1);
#ifdef _WIN32
		Sleep(sec * 1000);
#else
        sleep(sec);
#endif
    }
    return 0;
}
//------------------------------------------------------------------------------
/*
 * LUA-registered file I/O
 */
#ifdef __cplusplus
extern "C"
#endif
int lua_rawreadfile(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != 1) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "rawreadfile() was called with %d arguments, %d arguments required",
                args, 1);
        lua_pushboolean(state, 0);//result
        lua_pushnil(state);
        lua_pushnumber(state, 0);
    } else {
        char *fname = (char *)lua_tostring(state, 1);
        size_t image_sz = 0;
        if(unsigned char *image = loadBufferFromFile(fname, image_sz, Status)) {
            if(auto lua_image = (unsigned char *)lua_newuserdata(state, image_sz)) {
                memcpy(lua_image, image, image_sz);
                lua_pushboolean(state, 1);//result
                lua_pushlightuserdata(state, lua_image);
                lua_pushnumber(state, (lua_Number)image_sz);
            } else {
                lua_pushboolean(state, 0);//result
                lua_pushnil(state);
                lua_pushnumber(state, 0);
                sprintf(Status,
                        "rawreadfile(): LUA memory allocation error");
            }
            delete[] image;
        } else {
            lua_pushboolean(state, 0);//result
            lua_pushnil(state);
            lua_pushnumber(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 4;//result, image, image size, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_rawwritefile(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != 3) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "rawwritefile() was called with %d arguments, %d arguments required",
                args, 3);
        lua_pushboolean(state, 0);//result
    } else {
        char *fname = (char *)lua_tostring(state, 1);
        auto image = (unsigned char *)lua_touserdata(state, 2);
        auto image_sz = (size_t)lua_tonumber(state, 3);
        if(saveBufferToFile(fname, image, image_sz, Status)) {
            lua_pushboolean(state, 1);//result
            sprintf(Status,
                    "rawwritefile(): file %s written successfully", fname);
        } else {
            lua_pushboolean(state, 0);//result
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status text
}
//------------------------------------------------------------------------------
/*
 * LUA-registered wrappers for cryptographical functions
 */
const int c_gen_keys_pair_args = 0;
const int c_hash_args = 2;
const int c_verify_args = 4;
const int c_sign_args = 4;

const int c_get_db_name_args = 0;
const int c_init_db_args = 3;
const int c_deinit_db_args = 1;
const int c_db_insert_args = 5;
const int c_db_obtain_args = 3;
const int c_db_index_args = 3;
const int c_db_del_args = 3;
const int c_db_keys_args = 1;
const int c_db_enum_args = 3;

const int c_init_serv_args = 4;
const int c_stop_serv_args = 0;
const int c_is_serv_args = 0;
const int c_recv_args = 0;
const int c_sendto_args = 4;
const int c_append_host_args = 2;

const int c_cmd_iam_args = 2;
const int c_cmd_heis_args = 5;
const int c_cmd_get_entity_args = 3;
const int c_present_me_args = 0;
const int c_full_index_args = 0;

#ifdef __cplusplus
extern "C"
#endif
int lua_hash(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != c_hash_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "hash() was called with %d arguments, %d arguments required",
                args, c_hash_args);
    } else {
        auto data = (unsigned char *)lua_touserdata(state, 1);
        auto data_sz = (size_t)lua_tonumber(state, 2);
        auto hash = (unsigned char *)lua_newuserdata(state, hash_type::get_sz());
        if(blake2(hash,
                  hash_type::get_sz(),
                  data,
                  data_sz,
                  nullptr,
                  0) == 0)
        {
            sprintf(Status, "%s hash", "Data");
            lua_pushboolean(state, 1);
            lua_pushlightuserdata(state, hash);
            lua_pushinteger(state, hash_type::get_sz());
        } else {
            logger.dbg("blake2 error");
            sprintf(Status, "%s hash failure", "Data");
            lua_pushboolean(state, 0);
            lua_pushnil(state);
            lua_pushinteger(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 4;//result, hash, hash size, status text
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Подпись блока данных
 * Входные параметры:
 * unsigned char* data -- указатель на блок данных
 * unsigned int data_sz -- размер подписываемого блока данных
 * unsigned char* public_key -- указатель на 32-байтный массив, содержащий публичный ключ
 * unsigned char* private_key -- указатель на 64-байтный массив, содеражщий секретный ключ
 * Выходные параметры:
 * bool result -- результат операции
 * unsigned char* signature -- подпись, массив размером 64 байта; NULL в случае ошибки
 * unsigned int signature)sz -- размер подписи; 0 в случае ошибки, иначе всегда 64 байта
 * char* status -- стркоа с описанием ошибки
 * Пример:
 * result, public_key, public_key_sz, private_key, private_key_sz, status = gen_keys_pair)
 * if result then
 * 	result, signature,m signature_sz, status = sign(image, image_sz, public_key, private_key)
 * end
 */
int lua_sign(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != c_sign_args) {
        lua_pushboolean(state, 0);
        lua_pushnil(state);//signature
        lua_pushnumber(state, 0);//signature size
        sprintf(Status,
                "sign() was called with %d arguments, %d arguments required",
                args, c_sign_args);
    } else {
        auto data = (unsigned char *)lua_touserdata(state, 1);
        auto data_sz = (size_t)lua_tonumber(state, 2);
        auto public_key = (unsigned char *)lua_touserdata(state, 3);
        auto private_key = (unsigned char *)lua_touserdata(state, 4);

        //TODONOT: do not use new or malloc, lua_newuserdata: LUA garbage collector deallocates it
        auto signature = (unsigned char *)lua_newuserdata(state, sign_type::get_sz());

        if(sign(data,
                data_sz,
                public_key,
                public_type::get_sz(),
                private_key,
                private_type::get_sz(),
                signature,
                sign_type::get_sz(),
                Status,
                COUNT(Status)))
        {
            lua_pushboolean(state, 1);//result
            lua_pushlightuserdata(state, signature);//signature
            lua_pushnumber(state, sign_type::get_sz());//signature size
            sprintf(Status, "%s obtained", SIGNATURE_STR);
        } else {
            lua_pushboolean(state, 0);//result
            lua_pushnil(state);//signature
            lua_pushnumber(state, 0);//signature size
        }
    }
    lua_pushstring(state, Status);
    return 4;//result, signature, signature size, status text
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Проверка подписи блока данных
 * Входные параметры:
 * unsigned char* data -- указатель на блок данных
 * unsigned int data_sz -- размер подписываемого блока данных
 * unsigned char* public_key -- указатель на 32-байтный массив, содержащий публичный ключ
 * unsigned char* signature -- указатель на 64-байтный массив, содержащий подпись
 * Выходные параметры:
 * bool result -- результат операции
 * char* status -- строка с описанием ошибки
 * Пример:
 * result, public_key, public_key_sz, private_key, private_key_sz, status = gen_keys_pair()
 * if not result then do return end end
 * rsult, signature, signature_sz, status = sign(image, image_sz, public_key, private_key)
 * print(status)
 * if not result then do return end end
 * result, status = verify(image, image_sz, public_key, signature)
 * print(status)
 */
int lua_verify(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != c_verify_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "verify() was called with %d arguments, %d arguments required",
                args, c_verify_args);
    } else {
        auto data = (unsigned char *)lua_touserdata(state, 1);
        auto data_sz = (size_t)lua_tonumber(state, 2);
        auto public_key = (unsigned char *)lua_touserdata(state, 3);
        auto signature = (unsigned char *)lua_touserdata(state, 4);
        if(verify(data,
                data_sz,
                public_key,
                public_type::get_sz(),
                signature,
                sign_type::get_sz(),
                Status,
                COUNT(Status)))
        {
            sprintf(Status, "%s checked", SIGNATURE_STR);
            lua_pushboolean(state, 1);
        } else {
            //Status filled inside verify() function
            lua_pushboolean(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status text
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Инициализация пары ключей
 * Возвращает следующие значения в lua:
 * bool result -- результат операции
 * unsigned char* public_key -- публичный ключ, массив размером 32 байта; NULL в случае ошибки
 * unsigned int public_key_sz -- размер публичного ключа; 0 в случае ошибки, иначе всегда 32 байта
 * unsigned char* private_key -- секретный ключ, массив размером 64 байта; NULL в случе ошибки
 * unsigned int private_key_sz -- размер публичного ключа; 0 в случае ошибки, иначе всегда 64 байта
 * char* status -- строка с описанием ошибки
 *
 * Пример:
 * io.write("Calling gen_keys_pair() ...\n)
 * result_str = "failure"
 * result, public_key, public_key_sz, private_key, private_key_sz, status = gen_keys_pair()
 * if result then result_str = "success" end
 * io.write(string.format("gen_keys_pair() returned %s: %s\n", result_str, tostring(status)))
 */
int lua_gen_keys_pair(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != c_gen_keys_pair_args) {
        lua_pushboolean(state, 0);
        lua_pushnil(state);//public key
        lua_pushnumber(state, 0);//public key size
        lua_pushnil(state);//private key
        lua_pushnumber(state, 0);//private key size
        sprintf(Status,
                "gen_keys_pair() was called with %d arguments, no arguments required",
                args);
        lua_pushstring(state, Status);
    } else {
        //TODONOT: do not use new or malloc, lua_newuserdata: LUA garbage collector deallocates it
        auto public_key = (unsigned char *)lua_newuserdata(state, public_type::get_sz());
        auto private_key = (unsigned char *)lua_newuserdata(state, private_type::get_sz());
        if(gen_keys_pair(public_key,
                public_type::get_sz(),
                private_key,
                private_type::get_sz(),
                Status,
                COUNT(Status)))
        {
            sprintf(Status,
                    "Keys pair successfully generated: %zu bytes of public key, %zu bytes of private key",
                    public_type::get_sz(),
                    private_type::get_sz());
            lua_pushboolean(state, 1);
            lua_pushlightuserdata(state, public_key);
            lua_pushnumber(state, public_type::get_sz());
            lua_pushlightuserdata(state, private_key);
            lua_pushnumber(state, private_type::get_sz());
        } else {
            lua_pushboolean(state, 0);
            lua_pushnil(state);//public key
            lua_pushnumber(state, 0);//public key size
            lua_pushnil(state);//private key
            lua_pushnumber(state, 0);//private key size
        }
        lua_pushstring(state, Status);
    }
    return 6;
}
//------------------------------------------------------------------------------
/*
 * LUA-registered wrappers for database access
 */
#ifdef __cplusplus
extern "C"
#endif
int lua_init_database(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_init_db_args) {
        lua_pushboolean(state, 0);
        lua_pushnil(state);
        sprintf(Status,
                "init_database() was called with %d arguments, %d arguments required",
                args, c_init_db_args);
    } else {
		if (db_singleton.initialized()) {
			lua_pushboolean(state, 1);
			lua_pushlightuserdata(state, &db_singleton);
			sprintf(Status, "Database %s initialized successfully", db_singleton.getDbName().c_str());
		}
		else {
			lua_pushboolean(state, 0);
			lua_pushnil(state);
			sprintf(Status, "Database %s not initialized", db_singleton.getDbName().c_str());
		}
		//char *fname = (char *)lua_tostring(state, 1);
  //      auto ppublic_key = (const public_type *)lua_touserdata(state, 2);
  //      auto pprivate_key = (const private_type *)lua_touserdata(state, 3);
		////db_singleton = new RA_DB_SINGLETON();
  //      if(auto db_handler = &db_singleton) {
  //          if(ppublic_key && pprivate_key) {
  //              if (db_handler->init(fname, *ppublic_key, *pprivate_key, Status, COUNT(Status))) { // TODO: ->init
  //                  lua_pushboolean(state, 1);
  //                  lua_pushlightuserdata(state, db_handler);
  //                  sprintf(Status, "Database %s initialized successfully", fname);
  //              } else {
  //                  lua_pushboolean(state, 0);
  //                  lua_pushnil(state);
  //              }
  //          } else {
  //              if (db_handler->init(fname, Status, COUNT(Status))) {
  //                  lua_pushboolean(state, 1);
  //                  lua_pushlightuserdata(state, db_handler);
  //                  sprintf(Status, "Database %s initialized successfully", fname);
  //              } else {
  //                  lua_pushboolean(state, 0);
  //                  lua_pushnil(state);
  //              }
  //          }
  //      } else {
  //          lua_pushboolean(state, 0);
  //          lua_pushnil(state);
  //          sprintf(Status,
  //                  "init_database(): LUA memory allocation error");
  //      }
    }
    lua_pushstring(state, Status);
    return 3;//result, handler, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_get_db_keys(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_keys_args) {
        lua_pushboolean(state, 0);
        lua_pushnil(state);//Public key
        lua_pushnil(state);//Private key
        sprintf(Status,
                "deinit_database() was called with %d arguments, %d arguments required",
                args, c_deinit_db_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            public_type &public_key = db_handler->getDbPublicKey();
            private_type &private_key = db_handler->getDbPrivateKey();
            lua_pushboolean(state, 1);
            lua_pushlightuserdata(state, public_key.data);
            lua_pushlightuserdata(state, private_key.data);
        } else {
            sprintf(Status,
                    "db_keys(): database is NULL");
        }
    }
    lua_pushstring(state, Status);
    return 4;//result, public key, private key, status str
}
#ifdef __cplusplus
extern "C"
#endif
int lua_deinit_database(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_deinit_db_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "deinit_database() was called with %d arguments, %d arguments required",
                args, c_deinit_db_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            if(db_handler->deinit(Status, COUNT(Status))) {
                lua_pushboolean(state, 1);
                sprintf(Status, "Database deinitialized successfully");
                delete db_handler;
            } else {
                lua_pushboolean(state, 0);
            }
        } else {
            lua_pushboolean(state, 0);
            sprintf(Status,
                    "deinit_database(): database is NULL");
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_insert(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_insert_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "db_isert() was called with %d arguments, %d arguments required",
                args, c_db_insert_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_key = (unsigned char *) lua_touserdata(state, 2); //that's hash
            auto db_key_sz = (size_t)lua_tonumber(state, 3);
            auto db_data = (unsigned char *) lua_touserdata(state, 4);
            auto db_data_sz = (size_t)lua_tonumber(state, 5);
            if(db_handler->interlocked_insert(db_key,
                    db_key_sz,
                    db_data,
                    db_data_sz,
                    lmLoad,
                    Status,
                    COUNT(Status)))
            {
                lua_pushboolean(state, 1);
                if(!strlen(Status)) sprintf(Status, "Record inserted to database");
            } else {
                lua_pushboolean(state, 0);
            }
        } else {
            sprintf(Status,
                    "db_insert(): database is NULL");
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_obtain(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_obtain_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "db_obtain() was called with %d arguments, %d arguments required",
                args, c_db_obtain_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_key = (unsigned char *) lua_touserdata(state, 2); //that's hash
			auto db_key_sz = (size_t)lua_tonumber(state, 3);
            unsigned char *db_data = nullptr;
            size_t db_data_sz = 0;

            if(db_handler->interlocked_obtain(db_key,
                                  db_key_sz,
                                  db_data,
                                  db_data_sz,
                                  lmLoad,
                                  Status,
                                  COUNT(Status)))
            {
                //auto lua_data =(unsigned char *)lua_newuserdata(state, db_data_sz);
                //memcpy(lua_data, db_data, db_data_sz);
                lua_pushboolean(state, 1);//result
                //lua_pushlightuserdata(state, lua_data);//data
                lua_pushlightuserdata(state, db_data);//data
                lua_pushnumber(state, (lua_Number)db_data_sz);//data size
                sprintf(Status, "Record of %u bytes size obtained from database", (unsigned int)db_data_sz);
            } else {
                lua_pushboolean(state, 0);//result
                lua_pushnil(state);//data
                lua_pushnumber(state, 0);//data size
            }
        }
    }
    lua_pushstring(state, Status);//status
    return 4;//result, data, data size, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_index(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    if(args != c_db_index_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "db_index() was called with %d arguments, %d argiments required",
                args, c_db_index_args);
    }
    else {
        if (auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_block = (unsigned char *) lua_touserdata(state, 2);
            auto db_block_sz = (size_t)lua_tonumber(state, 3);
			/*META_INFO m;
			ZEROIZE(&m);*/
            if(db_handler->index(db_block, db_block_sz)) {
                lua_pushboolean(state, 1);
                sprintf(Status, "Block indexed");
				//if (db_singleton.hSync)
					//memcpy(&db_singleton.hSync->hashes.prev_hash, &m.prev_hash, sizeof(hash_type));
            }
            else {
                lua_pushboolean(state, 0);
            }
        }
    }
    lua_pushstring(state, Status);
    return 2;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_del(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_del_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "db_del() was called with %d arguments, %d arguments required",
                args, c_db_del_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_key = (unsigned char *) lua_touserdata(state, 2);
            auto db_key_sz = (size_t)lua_tonumber(state, 3);

            if(db_handler->interlocked_del(db_key, db_key_sz, Status, COUNT(Status))) {
                lua_pushboolean(state, 1);
                sprintf(Status, "Value removed from database successfully");
            } else {
                lua_pushboolean(state, 0);
            }
        } else {
            lua_pushboolean(state, 0);
            sprintf(Status,
                    "db_del(): database is NULL");
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status text
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_enumerate(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_enum_args) {
        lua_pushboolean(state, 0);
        lua_newtable(state);
        sprintf(Status,
                "db_enumerate() was called with %d arguments, %d arguments required",
                args, c_db_enum_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_key = (unsigned char *) lua_touserdata(state, 2);
            auto db_key_sz = (size_t) lua_tonumber(state, 3);
			std::list<std::string> fnames = db_handler->interlocked_enumerate(db_key, db_key_sz, lmEmpty, 0, (~(size_t)0), Status, COUNT(Status));
            lua_pushboolean(state, !fnames.empty());
            lua_newtable(state);
            int i = 0;
            for(auto &fname : fnames) {
                lua_pushnumber(state, i);
                lua_pushstring(state, fname.c_str());
                lua_rawset(state, -3);//pops pair from stack
                i++;
            }
        }
    }
    lua_pushstring(state, Status);
    return 3;//result, table, string
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_enum_keys(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_db_enum_args) {
        lua_pushboolean(state, 0);
        lua_newtable(state);
        sprintf(Status,
                "db_enumerate() was called with %d arguments, %d arguments required",
                args, c_db_enum_args);
    } else {
        if(auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
            auto db_key = (unsigned char *)lua_touserdata(state, 2);
            auto db_key_sz = (size_t) lua_tonumber(state, 3);
			std::list<key_type> keys = db_handler->interlocked_enum_keys(db_key, db_key_sz, lmEmpty, 0, ~0, Status, COUNT(Status));
            lua_pushboolean(state, !keys.empty());
            lua_newtable(state);
            int i = 0;
            for(auto &key : keys) {
                lua_pushnumber(state, i);
                auto lua_key = new key_type();
                memcpy(lua_key->data, key.data, sizeof(key_type));
                lua_pushlightuserdata(state, lua_key);
                lua_rawset(state, -3);//pops pair from stack
                i++;
            }
        }
    }
    lua_pushstring(state, Status);
    return 3;//result, table, string
}
//------------------------------------------------------------------------------
/*
 * LUA-registered wrappers for networking
 */

#ifdef __cplusplus
extern "C"
#endif
/*
 * Запуск сетевого сервиса в отдельном потоке
 * Входные параметры:
 * const char *address -- адрес, на котором слушает сервис; в случае пустой строки INADDR_ANY
 * const ushort port -- порт, на котором слушает сервис; в случае 0 порт по умолчанию, в данный момент 56000
 * Выходные параметры:
 * bool result -- рузельтат операции;
 * char* status -- строка с описанием ошибки
 */
int lua_net_serv(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_init_serv_args) {
        lua_pushboolean(state, 0);//result
        sprintf(Status,
                "net_serv() was called with %d arguments, %d arguments required",
                args, c_init_serv_args);
    } else {
        auto ppublic_key = (const public_type *)lua_touserdata(state, 1);
        auto pprivate_key = (const private_type *)lua_touserdata(state, 2);

		const char *hostname = NET_ADDR; // lua_tostring(state, 3);//host address; if "" then INADDR_ANY address used
		unsigned short port = 0; //(unsigned short)lua_tonumber(state, 4);//port; is ZERO then default port used
        if(net_launch(*ppublic_key, *pprivate_key, hostname, port)) {
            lua_pushboolean(state, 1);//result
            sprintf(Status, "Network service initialized successfully");
        } else {
			sprintf(Status, "Network service initialization fault");
            lua_pushboolean(state, 0);//result
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Остановка сетевого сервиса
 * Выходные параметры:
 * bool result -- рузультат операкции
 * char* status -- строка с описанием ошибки
 */
int lua_net_stop(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_stop_serv_args) {
        lua_pushboolean(state, 0);//result
        sprintf(Status,
                "net_stop() was called with %d arguments, %d arguments required",
                args, c_stop_serv_args);
    } else {
		net_stop();
        if(net_available()) {
            lua_pushboolean(state, 0);//result
            sprintf(Status,
                    "net_stop() error");
        } else {
            lua_pushboolean(state, 1);//result
            sprintf(Status,
                    "Networking stopped");
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Проверка доступности сети
 * Выходные параметры:
 * bool result -- результат операции
 * bool state -- солстояние сети
 * char* status -- строка с описанием ошибки
 */
int lua_net_available(lua_State *state) {
	logger.dbg("Networking check");
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_is_serv_args) {
        lua_pushboolean(state, 0);//result
        lua_pushboolean(state, 0);//state
        sprintf(Status,
                "net_available() was called with %d arguments, %d arguments required",
                args, c_is_serv_args);
    } else {
        bool b_state = net_available();
        if(b_state) {
            sprintf(Status, "Networking on");
        } else {
            sprintf(Status, "Networking off");
        }
        lua_pushboolean(state, 1);//result
        lua_pushboolean(state, b_state);//state
    }
    lua_pushstring(state, Status);
    return 3;//result, state, status
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Получение собранного буферпа дейстаграмм
 * Дейтаграммы, состоавляющие один буфер, могут теоретически приходить с разных хостов,
 * поэтому адрес хоста-отправителя не возвращается.
 * Фрагментация данных позволяет передавать по протоколу UDP большие блоки информации,
 * при этом информация структурируется.
 * Выходные параметры:
 * bool result -- результат операции
 * const unsigned char* buffer -- буфер, содержащий отправляемые данные
 * const size_t buffer_sz -- рамер отправляемых данных
 * char* status -- строка с описанием ошибки
 */
int lua_net_recv(lua_State *state) {
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
    try {
        int args = lua_gettop(state);

        if (args != c_recv_args) {
            logger.err("args count error");
            lua_pushboolean(state, 0);//result
            lua_pushnil(state);//data
            lua_pushinteger(state, 0);//data_sz
            sprintf(Status,
                    "net_recv() was called with %d arguments, %d arguments required",
                    args, c_recv_args);
        } else {
            auto buffer = (unsigned char *) lua_newuserdata(state, MAX_PACKAGE_SZ);
            if (buffer) {
                size_t buffer_sz = MAX_PACKAGE_SZ;
				ENTITY_DATA_TYPE data_type;
                if (net_recv(buffer, buffer_sz, data_type, Status, COUNT(Status))) {
					if (data_type !=edtTransaction)
					{
						lua_pushboolean(state, 1);//result
						lua_pushlightuserdata(state, buffer);//data
						lua_pushinteger(state, (int)buffer_sz);//data_sz
						lua_pushinteger(state, (int)data_type); //entity data type
						sprintf(Status, "%zu bytes received", buffer_sz);
					}
					else {
						lua_pushboolean(state, 0);//result
						lua_pushnil(state);//data
						lua_pushinteger(state, 0);//data_sz
						lua_pushinteger(state, (int)data_type); //entity data type
						sprintf(Status, "redirected transaction been received");
					}
                } else {
					if (strcmp(Status, "No received data available")) {
						logger.err("receive error");
					}
					/*
					else
						logger.dbg("no data received");
					*/
                    lua_pushboolean(state, 0);//result
                    lua_pushnil(state);//data
                    lua_pushinteger(state, 0);//data_sz
					lua_pushinteger(state, 0);
                }
            } else {
                logger.err("buffer allocation error");
                lua_pushboolean(state, 0);//result
                lua_pushnil(state);//data
                lua_pushinteger(state, 0);//data_sz
				lua_pushinteger(state, 0);
                sprintf(Status,
                        "Receiving buffer allocation error");
            }
        }
    } catch(const std::exception &e) {
        logger.exc("extract_received: %s", e.what());
        lua_pushboolean(state, 0);//result
        lua_pushnil(state);//data
        lua_pushinteger(state, 0);//data_sz
		lua_pushinteger(state, 0);
        sprintf(Status,
                "Exception during receive");
    }
    lua_pushstring(state, Status);
    return 5;//result, data, data_sz, data_type,status
}

#ifdef __cplusplus
extern "C"
#endif
/*
 * Отправка буфера по адресу
 * Данные разбиваются на дейтаграммы, помещаются в специальную управляющую структуру,
 * которая встаёт в очередь отправки.
 * Входные параметры:
 * const unsigned char* buffer -- буфер, содеражщий отправляемые данные
 * const size_t buffer_sz -- размер отправляемых данных
 * const char( hostname -- адрес целевогохоста
 * const unsigned short -- порт, на котором слушает сервис целевого хоста; если 0, используется номер порта по умолчанию
 * Выходные параметры:
 * bool result -- результат операкции
 * char* status -- строка с описанием ошибки
 */
int lua_net_sendto(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_sendto_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "net_sendto() was called with %d arguments, %d arguments required",
                args, c_sendto_args);
    } else {
        auto buffer = (unsigned char *)lua_touserdata(state, 1);
        auto buffer_sz = (size_t)lua_tonumber(state, 2);
        auto hostname = (char *)lua_tostring(state, 3);
        auto port = (unsigned short)lua_tonumber(state, 4);

        if(net_sendto(hostname, port, buffer, buffer_sz, ENTITY_DATA_TYPE::edtBlock, Status, COUNT(Status))) {
            lua_pushboolean(state, 1);
            sprintf(Status, "%zu bytes sent to %s:%d", buffer_sz, hostname, port);
        } else {
            lua_pushboolean(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
int lua_net_command_iam_to(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_cmd_iam_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "net_command_iam_to() was called with %d arguments, %d arguments required",
                args, c_cmd_iam_args);
    } else {
        
		if(auto _hosts = (sHosts*)lua_touserdata(state,1)){ //TODO взять список из db_handler??
            auto& h  =_hosts->values;
            bool ok = true;
            for(auto& it:h){
                ok *= net_command_iam(it.first.c_str(), it.second, Status, COUNT(Status));
                if(!ok){
                    sprintf(Status, "Command 'I am' sent to %s:%d", it.first.c_str(), it.second);
                    break;
                }
            }
            lua_pushboolean(state, ok);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
int lua_net_command_heis_to(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_cmd_heis_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "net_command_heis_to() was called with %d arguments, %d arguments required",
                args, c_cmd_heis_args);
    } else {
        auto hostname = (char *)lua_tostring(state, 1);
        auto port = (unsigned short)lua_tonumber(state, 2);
        auto ppublic_key = (public_type *)lua_touserdata(state, 3);
        auto his_hostname = (char *)lua_tostring(state, 4);
        auto his_port = (unsigned short)lua_tonumber(state, 5);

        if(net_command_heis(hostname, port, *ppublic_key, his_hostname, his_port, Status, COUNT(Status))) {
            lua_pushboolean(state, 1);
            sprintf(Status, "Command %u sent to %s:%d", protoHeIs, hostname, port);
        } else {
            lua_pushboolean(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}


#ifdef __cplusplus
extern "C"
#endif
int lua_net_command_get_entity(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_cmd_get_entity_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "net_command_get_entity() was called with %d arguments, %d arguments required",
                args, c_cmd_iam_args);
    } else {
        auto pentity_hash = (hash_type *)lua_touserdata(state, 1);
        auto hostname = (char *)lua_tostring(state, 2);
        auto port = (unsigned short)lua_tonumber(state, 3);

        if(net_command_get_entity(hostname, port, *pentity_hash, Status, COUNT(Status))) {
            lua_pushboolean(state, 1);
            sprintf(Status, "Command %u sent to %s:%d", protoGetEntity, hostname, port);
        } else {
            lua_pushboolean(state, 0);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}

#ifdef __cplusplus
extern "C"
#endif
int lua_present_me(lua_State *state) {
	int args = lua_gettop(state);
	char Status[MINIMAL_STATUS_LENGTH] = {'\0'};
	if(args != c_present_me_args) {
		lua_pushboolean(state, 0);
		sprintf(Status,
				"present_me was called with %d arguments, %d arguments required",
				args, c_present_me_args);
	}
	else {
		std::thread th(net_present_me);
		th.detach();
		if(!th.joinable()) {
			sprintf(Status, "present_me has started");
		}
		else {
			sprintf(Status, "present_me has failed to start");
		}
	}
	lua_pushstring(state, Status);
	return 2;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_synclasthash(lua_State *state) {
	//int args = lua_gettop(state);
	//char uStatus[MINIMAL_STATUS_LENGTH] = { '\0' };
	//int result = net_synclasthash();
	/*std::thread tr(net_synclasthash);
	tr.detach();
	int result = tr.joinable();
	if (!result)
		sprintf(uStatus, "Sync request invoked");
	else
		sprintf(uStatus, "Sync request failed");*/
	int result = net_synclasthash();
	lua_pushstring(state, result !=0 ? "last hash send failed!" : "last hash sended");
	return 2;

}
#ifdef __cplusplus
extern "C"
#endif 
 int lua_db_checksync(lua_State *state) {
	//исправление 09.01 - вместо true\false возвращает числовой статус синхронизации (0 - не запущено; 1 - запущено; 2 - завершено)
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	switch (db_singleton.hSync.SyncState())
	{
	case SyncHandler::eSyncNotLanch:
		sprintf(Status, "synchronization not lanch");
		break;
	case SyncHandler::eSyncLanch:
		//sprintf(Status, "sycronization continue");
		break;
	default:
		sprintf(Status, "synchronization complete");
		break;
	}
	lua_pushinteger(state, db_singleton.hSync.SyncState());	
	lua_pushstring(state, Status);
	lua_pushlightuserdata(state, &db_singleton.hSync.top_hash);
 	return 3;	
}//result,status,null or newlasthash


#ifdef __cplusplus
extern "C"
#endif
int lua_db_setlasthash(lua_State *state) {
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	int args = lua_gettop(state);
	if (args != 2)
		return 0;
	else {
		if (auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
			auto hash = (unsigned char *)lua_touserdata(state, 2);
			
			std::string fname = db_handler->getDbPath() + "/.EXT/last";
			if (saveBufferToFile(fname.c_str(), hash, 64, nullptr)) {
				sprintf(Status, "file .EXT/last written successfully");
				lua_pushboolean(state, 1);
			}
			else
			{
				sprintf(Status, "file .EXT/last written ERROR");
				lua_pushboolean(state, 0);
			}
			lua_pushstring(state, Status);			
		}
		return 2;
	}
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_full_index(lua_State *state) {
    char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
    int args = lua_gettop(state);
    if (args != c_full_index_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "db_full_index was called with %d arguments, %d arguments required",
                args, c_full_index_args);
    }
    else {
        db_singleton.full_index();
    }
    lua_pushstring(state, Status);
    return 2; // result, status text
}

#ifdef __cplusplus
extern "C"
#endif 
int lua_db_checkintegrity(lua_State *state) {
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	bool checkHashes = false;
	int args = lua_gettop(state);
	if (args >= 1)
	{
		checkHashes = lua_toboolean(state,1);		
	}
	//else {
		/*if (auto db_handler = (DbHandler *)lua_touserdata(state, 1)) {
			hash_type needhash;*/
			if (!db_singleton.checkIntegrityChain(checkHashes)) {
				sprintf(Status, "chain integrity failed!");
				lua_pushboolean(state, 0);
				lua_pushstring(state, Status);
				//lua_pushlightuserdata(state, &needhash);
				return 2;
			}
			else {
				sprintf(Status, "chain integrity complete");
				lua_pushboolean(state, 1);
				lua_pushstring(state, Status);
				//lua_pushnil(state);
				return 2;
			}
		//}

	//} //result, status
}

#ifdef __cplusplus
extern "C"
#endif
int lua_db_initsyncproc(lua_State *state) {
	char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	if (db_singleton.hSync.SyncState() == SyncHandler::eSyncLanch ) {
		auto sync_thread = new std::thread(net_sync_proc);
		sync_thread->detach();
		if (!sync_thread->joinable()) {
			sprintf(Status, "sync proc started");
			lua_pushboolean(state, 1);
		}
		else {
			sprintf(Status, "sync proc failed!");
			lua_pushboolean(state, 0);
		}
	}
	lua_pushstring(state, Status);
	return 2;
}//result, status

#ifdef __cplusplus
extern "C"
#endif
int lua_net_round_broadcast(lua_State *state) {
	//char Status[MINIMAL_STATUS_LENGTH] = { '\0' };
	std::thread th(net_round_broadcast);
	th.detach();
	return 0;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_net_getfriendlyhost(lua_State *state) { //возвращает адрес и порт хоста для запроса GetEntity; пока - 1й в списке, затем - по приоритетам
	if (auto _hosts = (Hosts*)lua_touserdata(state, 1)) {

	}
	return 0;
}

#ifdef __cplusplus
extern "C"
#endif
int lua_net_checkstopflag(lua_State *state) { //если выставлен флаг завершения работы - сбрасывает его и возвращает true, иначе - false
	if (FULLSTOP_FLG == 0)
		lua_pushboolean(state, 0);
	else {
		FULLSTOP_FLG = 0;
		lua_pushboolean(state, 1);
	}
	return 1;
}

/*
#ifdef __cplusplus
extern "C"
#endif
int lua_net_appendhost(lua_State *state) {
    int args = lua_gettop(state);
    char Status[MINIMAL_STATUS_LENGTH] = {'\0'};

    if(args != c_append_host_args) {
        lua_pushboolean(state, 0);
        sprintf(Status,
                "net_appendhost() was called with %d arguments, %d arguments required",
                args, c_append_host_args);
    } else {
        auto hostname = (char *)lua_tostring(state, 1);
        auto port = (unsigned short)lua_tonumber(state, 2);

        sockaddr_in addr = {0};
        addr.sin_port = htons(port ? port : UDP_PORT);
#ifdef _WIN32
		addr.sin_addr.S_un.S_addr = inet_addr(hostname);
		if(addr.sin_addr.S_un.S_addr == INADDR_NONE) {
#else
        if(!inet_aton(hostname, &addr.sin_addr)) {
#endif
            logger.warn("%s not resolved by inet_aton", hostname);
            struct hostent *he = gethostbyname(hostname);
            if(he) {
                logger.dbg("gethostbyname got data for %s", hostname);
                switch(he->h_addrtype)
                {
                    case AF_INET:
                    {
                        logger.dbg("%s has address type AF_INET", hostname);
                        if(he->h_addr) {
                            struct in_addr **addr_list = (struct in_addr **)(he->h_addr_list);
                            if(addr_list[0]) {
                                logger.dbg("%s resolved to address %s", hostname, inet_ntoa(*addr_list[0]));
                                addr.sin_addr = *addr_list[0];
                                switch(hosts.appendHost(addr)) {
                                    case arAppended:
                                        lua_pushboolean(state, 1);
                                        sprintf(Status, "Got valid address %s:%d", hostname, port);
                                        break;
                                    case arAlreadyExists:
                                        lua_pushboolean(state, 1);
                                        sprintf(Status, "Got valid address %s:%d that already exists", hostname, port);
                                        break;
                                    case arNotAppended:
                                        lua_pushboolean(state, 0);
                                        sprintf(Status, "Got valid address %s:%d that was not appended", hostname,
                                                port);
                                        break;
                                    default:
                                        lua_pushboolean(state, 0);
                                        sprintf(Status, INTERNAL_ERR, -1);
                                        break;
                                }
                            } else {
                                lua_pushboolean(state, 0);
                                sprintf(Status, "Got invalid address %s", hostname);
                            }
                        } else {
                            lua_pushboolean(state, 0);
                            logger.err("hostent structure has empty addresses list");
                            sprintf(Status, "Got empty addresses list for %s", hostname);
                        }
                        break;
                    }
                    case AF_INET6:
                    {
                        lua_pushboolean(state, 0);
                        sprintf(Status, NOT_IMPLEMENTED);
                        break;
                    }
                    default:
                    {
                        lua_pushboolean(state, 0);
                        sprintf(Status, INTERNAL_ERR, h_errno);
                        break;
                    }
                }
            } else {
                lua_pushboolean(state, 0);
                sprintf(Status, INTERNAL_ERR, h_errno);
                logger.err("%s not resolved by gethostbyname", hostname);
            }
        } else {
            lua_pushboolean(state, 1);
            sprintf(Status, "Got valid address %s:%d", hostname, port);
        }
    }
    lua_pushstring(state, Status);
    return 2;//result, status
}
*/
//------------------------------------------------------------------------------
void bind_lua(lua_State *state) {
	//Register common functions
	lua_register(state, "msleep", lua_msleep);
    lua_register(state, "init_hosts", lua_init_hosts);
    lua_register(state, "deinit_hosts", lua_deinit_hosts);
    lua_register(state, "read_hosts", lua_read_hosts);

    //Register memory access functions wrappers
    lua_register(state, "hostalloc", lua_hostalloc);
    lua_register(state, "hostfree", lua_hostfree);
    lua_register(state, "hostread", lua_hostread);
    //Register file I/O functions wrappers for access from script
    lua_register(state, "rawreadfile", lua_rawreadfile);
    lua_register(state, "rawwritefile", lua_rawwritefile);
    //Register cryptographical functions wrappers for access from script
    lua_register(state, "ra_hash", lua_hash);
    lua_register(state, "sign", lua_sign);
    lua_register(state, "verify", lua_verify);
    lua_register(state, "gen_keys_pair", lua_gen_keys_pair);
    //Register database functions wrappers for access from script
    lua_register(state, "init_database", lua_init_database);
    lua_register(state, "get_db_keys", lua_get_db_keys);
    lua_register(state, "deinit_database", lua_deinit_database);
    lua_register(state, "db_insert", lua_db_insert);
    lua_register(state, "db_obtain", lua_db_obtain);
    lua_register(state, "db_index", lua_db_index);
    lua_register(state, "db_del", lua_db_del);
    lua_register(state, "db_enumerate", lua_db_enumerate);
    lua_register(state, "db_enum_keys", lua_db_enum_keys);
    //Register networking API
    lua_register(state, "net_recv", lua_net_recv);
    lua_register(state, "net_sendto", lua_net_sendto);
    lua_register(state, "net_serv", lua_net_serv);
    lua_register(state, "net_stop", lua_net_stop);
    lua_register(state, "net_available", lua_net_available);
    //Register networking control API
    lua_register(state, "cmd_iam", lua_net_command_iam_to);
    lua_register(state, "cmd_heis", lua_net_command_heis_to);
    lua_register(state, "cmd_get_entity", lua_net_command_get_entity);
    lua_register(state, "present_me", lua_present_me);
//        lua_register(state, "net_appendhost", lua_net_appendhost);
    //Sleep function
    lua_register(state, "hostsleep", lua_hostsleep);
	lua_register(state, "sync_lasthash", lua_db_synclasthash); // отсылает lasthash 1му хосту в списке - не себе
	lua_register(state, "setlasthash", lua_db_setlasthash); //записывает файл .EXT/last 
	lua_register(state, "db_checksync", lua_db_checksync); //проверка состояния синхронизации
    lua_register(state, "db_full_index", lua_db_full_index); //полный персчет индекса
	lua_register(state, "db_checkintegrity", lua_db_checkintegrity); //проверка целостности цепочки хешей, 0уровень (до 1 разрыва)
	lua_register(state, "db_initsyncproc", lua_db_initsyncproc); //запуск треда синхронизации
	lua_register(state, "net_checkstopflag", lua_net_checkstopflag);
	lua_register(state, "round_broadcast", lua_net_round_broadcast);
}

bool script_execute(const char *cScriptPath, const char *cScriptCallbacks, char *Status, size_t StatusSz) {
	SILENCE
    if(lua_State *state = luaL_newstate()) {//Initializing LUA state instance
        //Common libraries load for new LUA state instance
        luaL_openlibs(state);
        //Script load
        LUA_CALL(luaL_loadfile(state, cScriptPath), "Script file load");
        if (cScriptCallbacks) {
            bool b_load = handlers_pool.init_lua_src(cScriptCallbacks);
            b_load ?
            logger.log("Script callbacks initialized") :
            logger.err("Script callbacks initialization failure");
            if(b_load) {
                lua_State &l = handlers_pool.luaState();
                bind_lua(&l);
                /*
                handlers_pool.test();
                handlers_pool.test();
                handlers_pool.test();
                */
            }
        }
        bind_lua(state);
        //Launch script
        LUA_CALL(lua_pcall(state, 0, LUA_MULTRET, 0), "Script launch");
        //Free LUA state instance
        lua_close(state);
        return true;
    } else {
        SPRINTF(Status, "LUA State initialization failure\n");
    }
    return false;
}
//------------------------------------------------------------------------------
