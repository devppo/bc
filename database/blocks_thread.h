#pragma once

#include <stdlib.h>
#include <thread>
#include <atomic>

#include <common/macro.h>
#include <common/defs.h>

#include "block_type.h"
#include "database.h"

typedef struct DbSingletone : DbHandler {
private:
    std::atomic_bool on_service;
    bool blocks_launch();
    bool blocks_stop();
    static void blocks_thread_proc();
    std::thread *blocks_thread;
public:
    DbSingletone() : on_service(false), blocks_thread(nullptr) {
        //
    }
    ~DbSingletone() {
        blocks_stop();
        delete blocks_thread;
    }
    virtual bool init(const char *db_name,
			  char *Status = nullptr,
			  size_t StatusSz = 0);
    virtual bool init(const char *db_name,
			  const public_type &pub,
			  const private_type &priv,
			  char *Status = nullptr,
			  size_t StatusSz = 0);
} *PDbSingletone;

extern DbSingletone db_singleton;

