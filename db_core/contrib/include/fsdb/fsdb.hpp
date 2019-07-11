#pragma once

#include <string>
#include <filesystem>
#include <string_view>

bool save_buffer_to_file(const char *cFileName, const char *blob, const size_t cBlobSz);

class Fsdb {
public:
	Fsdb() : m_initialized(false), m_name("default") {

	}
	~Fsdb() {
        deinit();
	}
	bool init();
	bool deinit();
	bool initialized();
	std::string get_name();
	bool insert(std::string_view key, const char *pdata, const size_t data_sz);
	bool obtain(std::string_view key, const char *&pdata, size_t &data_sz);
private:
	bool m_initialized;
	std::string m_name;

	bool init_db_directory();
	std::filesystem::path get_db_record_path(std::string_view key);
};

