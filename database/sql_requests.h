#pragma once

#define SQL_INIT_HOSTS_TABLE "CREATE TABLE IF NOT EXISTS hosts(id INTEGER PRIMARY KEY AUTOINCREMENT, pubkey TEXT NOT NULL, address TEXT NOT NULL, port SMALLINT UNSIGNED, addr_type INTEGER, UNIQUE(address, port));"
//#define SQL_INIT_BALANCES_TABLE "CREATE TABLE IF NOT EXISTS balances(id INTEGER PRIMARY KEY AUTOINCREMENT, pubkey TEXT NOT NULL, high INT UNSIGNED, low BIGINT UNSIGNED, currency TEXT NOT NULL, last_scanned_block TEXT NOT NULL);"
#define SQL_INIT_BALANCES_TABLE "CREATE TABLE IF NOT EXISTS balances ( pubkey TEXT NOT NULL UNIQUE, high_in INT UNSIGNED, low_in BIGINT UNSIGNED, high_out INT UNSIGNED, low_out BIGINT UNSIGNED, currency TEXT, last_scanned_block TEXT, PRIMARY KEY(pubkey) );"
//#define SQL_INIT_BALANCES_INDEX "CREATE UNIQUE INDEX IF NOT EXISTS balances_idx ON balances ( pubkey ASC);"
#define SQL_INIT_TRS_PERSONAL_TABLE "CREATE TABLE IF NOT EXISTS trs_personal(id INTEGER PRIMARY KEY AUTOINCREMENT, b_hash TEXT NOT NULL, t_hash TEXT NOT NULL, high INT UNSIGNED, low BIGINT UNSIGNED);"
//#define SQL_INIT_IPS  "CREATE TABLE IF NOT EXISTS hosts (ip TEXT,port INTEGER, UNIQUE(ip,port));"
#define SQL_HOST_INSERT "INSERT OR IGNORE INTO hosts (pubkey, address, port) VALUES (?, ?, ?);"
#define SQL_HOST_SELECT "SELECT pubkey, address, port FROM hosts"
#define SQL_BALANCE_GET "SELECT pubkey, high_in, low_in, high_out,low_out, currency, last_scanned_block FROM balances"
#define SQL_BALANCE_GET_ANY "SELECT high_in, low_in, high_out,low_out, currency,last_scanned_block FROM balances WHERE pubkey=?"
#define SQL_BALANCE_INSERT "INSERT OR REPLACE INTO balances (pubkey, high_in, low_in, high_out,low_out, currency, last_scanned_block) VALUES (?,?,?,?,?,'PPO',?);"

#define SQL_GET_HOSTS               "SELECT pubkey, address, port, addr_type FROM hosts;"
// for restore chain chashe V
#define SQL_INIT_CHAINCASHE_TABLE "CREATE TABLE IF NOT EXISTS chain_cashe (id INTEGER PRIMARY KEY,ownhash TEXT NOT NULL)"
#define SQL_CHAINCASHE_INSERT "INSERT OR IGNORE INTO chain_cashe (id,ownhash) values (?,?)"
#define SQL_CHAINCASHE_SELECT "SELECT id,ownhash FROM chain_cashe ORDER BY id"
