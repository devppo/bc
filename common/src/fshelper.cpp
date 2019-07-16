#include "common/fshelper.h"
#ifdef _WIN32
#include <Windows.h>
#endif

const char *extract_fname(const char *fpath) {
	if (!fpath) return nullptr;
	if (!strlen(fpath)) return fpath;//nullptr?
	auto c_len = strlen(fpath);
	const char *fname = fpath + c_len;
	for (;;fname--) {
#ifdef WIN32
		if ((*PRED(fname) == '/') || (*PRED(fname) == '\\'))
			break;
#else
		if (*PRED(fname) == '/')
			break;
#endif
		if (fname == fpath) break;
	}
	return strlen(fname) ? fname : nullptr;
}

//------------------------------------------------------------------------------
bool dirExists(const char *path)
{
#ifdef WIN32
    WIN32_FIND_DATAA FindData = {0};
    HANDLE hFind = FindFirstFileA(path, &FindData);
    if (INVALID_HANDLE_VALUE == hFind) return false;
    bool result = !!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    FindClose(hFind);
    return result;
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    struct stat info = {0};
#pragma GCC diagnostic pop
    const std::string path_str(path);
    if (stat(path_str.c_str(), &info) != 0)
    {
        return false;
    } else {
        return ((info.st_mode & S_IFDIR) != 0);
    }
#endif
}

bool fileExists(const char *path)
{
#ifdef WIN32
    WIN32_FIND_DATAA FindData = {0};
    HANDLE hFind = FindFirstFileA(path, &FindData);
    if (INVALID_HANDLE_VALUE == hFind) return false;
    bool result = !(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY);
    FindClose(hFind);
    return result;
#else
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
    struct stat info = {0};
#pragma GCC diagnostic pop
    const std::string path_str(path);
    if (stat(path_str.c_str(), &info) != 0)
    {
        return false;
    } else {
        return ((info.st_mode & S_IFDIR) == 0);
    }
#endif
}

unsigned char *loadBufferFromFile(const char *cFileName,
        size_t &FileSz,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    if(FILE *f = fopen(cFileName, "r+b")) {
        fseek(f, 0, SEEK_END);
        FileSz = (unsigned int)ftell(f);
        if(!FileSz) {
            SPRINTF(Status, "File have zero size");
            fclose(f);
            return nullptr;
        }
        fseek(f, 0, SEEK_SET);
        try {
            auto result = new unsigned char[FileSz];
            auto cFileRead = fread(result, 1, FileSz, f);
            if(cFileRead == FileSz) {
                SPRINTF(Status, "%zu bytes read from File %s\n", cFileRead, cFileName);
                fclose(f);
                return result;
            } else {
                SPRINTF(Status, "File read error");
                delete[] result;
                fclose(f);
                return nullptr;
            }
        }
        catch (...) {
            SPRINTF(Status, "Buffer allocation error");
            fclose(f);
            return nullptr;
        }
    } else {
        SPRINTF(Status, "Blob file not found");
        return nullptr;
    }
}

bool saveBufferToFile(const char *cFileName,
        const unsigned char *Blob,
        const size_t cBlobSz,
        char *Status,
        size_t StatusSz)
{
    SILENCE

    bool result = false;
    if(FILE *f = fopen(cFileName, "w+b")) {
        if(fwrite(Blob, 1, cBlobSz, f) == cBlobSz) {
            SPRINTF(Status,
                    "File %s of %d bytes size written successfully",
                    cFileName,
                    (int)cBlobSz);
            result = true;
        } else {
            SPRINTF(Status, "File write error");
        }
        fclose(f);
    } else {
        SPRINTF(Status, "File open error");
    }
    return result;
}
//------------------------------------------------------------------------------
size_t dir_count(const std::string &dir) {
    size_t count = 0;
    auto pattern_path = dir + std::string("/*");
#ifdef WIN32
    //Check for directory exists
    WIN32_FIND_DATAA FindDir = {0};
    HANDLE hFindDir = FindFirstFileA(dir.c_str(), &FindDir);
    if (INVALID_HANDLE_VALUE == hFindDir) return (unsigned int)(~0);
	if (!(FindDir.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
		FindClose(hFindDir);
		return (unsigned int)(~0);
	}

    //Look for files in directory
    WIN32_FIND_DATAA FindData = {0};

    HANDLE hFind = FindFirstFileA(pattern_path.c_str(), &FindData);
    if (INVALID_HANDLE_VALUE != hFind) {
        do {
            count++;
        } while(FindNextFileA(hFind, &FindData));
        FindClose(hFind);
    }
#else
    //Check for directory exists

    struct stat info;
    ZEROIZE(&info);

    if(stat(dir.c_str(), &info)) return (unsigned int)(~(size_t)0);
    if(!(info.st_mode & S_IFDIR)) return (unsigned int)(~(size_t)0);

    //Look for files in directory
    glob_t glob_result;
    ZEROIZE(&glob_result);

    if(!glob(pattern_path.c_str(),
            GLOB_TILDE,
            nullptr,
            &glob_result))
    {
        count = glob_result.gl_pathc;
    }
    globfree(&glob_result);
#endif
    return count;
}

std::list<std::string> list_directory(const std::string &pattern,
        const std::string &dir,
        SearchFlags sf,
        size_t offset,
        size_t limit,
        char *Status,
        size_t StatusSz)
{
    SILENCE

	std::list<std::string> result;

    struct stat info;
    ZEROIZE(&info);

	std::string pattern_path = dir + std::string("/") + pattern;
#ifdef WIN32
    WIN32_FIND_DATAA FindData = {0};
	logger.dbg("FindFirstFileA: template %s", pattern_path.c_str());
    HANDLE hFind = FindFirstFileA(pattern_path.c_str(), &FindData);
    if (INVALID_HANDLE_VALUE != hFind) {
        auto n = 0;
		do {
			const char *c_extracted_fname = extract_fname(FindData.cFileName);
#ifdef _WIN32
			if (!_strcmpi(c_extracted_fname, ".")) continue;
			if (!_strcmpi(c_extracted_fname, "..")) continue;
			if (!_strcmpi(c_extracted_fname, ".KEYS")) continue;
			if (!_strcmpi(c_extracted_fname, "READ.ME")) continue;
#else
			if (!strcmpi(c_extracted_fname, ".")) continue;
			if (!strcmpi(c_extracted_fname, "..")) continue;
			if (!strcmpi(c_extracted_fname, ".KEYS")) continue;
			if (!strcmpi(c_extracted_fname, "READ.ME")) continue;
#endif
			switch (sf)
			{
			case sfAll:
			    if(n >= offset)
				    result.emplace_back(std::string(FindData.cFileName));
			    n++;
                if(result.size() >= limit) {
                    FindClose(hFind);
                    return result;
                }
				break;
			case sfFilesOnly: {
				//FILE_ATTRIBUTE_DIRECTORY;
				if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {}
				else {
    			    if(n >= offset)
	    			    result.emplace_back(std::string(FindData.cFileName));
		    	    n++;
                    if(result.size() >= limit) {
                        FindClose(hFind);
                        return result;
                    }
				}
				break;
			}
			case sfDirectoriesOnly: {
				if (FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
    			    if(n >= offset)
	    			    result.emplace_back(std::string(FindData.cFileName));
		    	    n++;
                    if(result.size() >= limit) {
                        FindClose(hFind);
                        return result;
                    }
				}
				break;
			}
			default:
				break;
			}
		} while(FindNextFileA(hFind, &FindData));
        FindClose(hFind);
	}
	else {
		logger.err("FindFirstFileA: template %s, error 0x%08X", pattern_path.c_str(), GetLastError());
	}
#else
    glob_t glob_result;
    ZEROIZE(&glob_result);

    int return_value = glob(pattern_path.c_str(),
            (sf == sfDirectoriesOnly) ?
            GLOB_ONLYDIR | GLOB_TILDE : GLOB_TILDE,
            nullptr,
            &glob_result);

    if(return_value != 0) {
        switch(return_value)
        {
            case GLOB_NOSPACE:
            {
                SPRINTF(Status, "glob() error: %s", "Ran out of memory");
                break;
            }
            case GLOB_ABORTED:
            {
                SPRINTF(Status, "glob() error: %s", "Read error");
                break;
            }
            case GLOB_NOMATCH:
            {
                SPRINTF(Status, "glob() error: %s", "No matches found");
                break;
            }
            case GLOB_NOSYS:
            {
                SPRINTF(Status, "glob() error: %s", "Not implemented");
                break;
            }
            default:
            {
                SPRINTF(Status, "glob() error: %s (%d)", INTERNAL_ERR, return_value);
                break;
            }
        }
    } else {

        struct stat info;
        ZEROIZE(&info);

        size_t n = 0;
        for(unsigned int i = 0; i < glob_result.gl_pathc; ++i) {
            switch (sf) {
                case sfAll: {
                    const char *current_path = glob_result.gl_pathv[i];
                    if(n >= offset)
                        result.emplace_back(std::string(current_path));
                    n++;
                    if(result.size() >= limit) {
                        globfree(&glob_result);
                        return result;
                    }
                    break;
                }
                case sfFilesOnly: {
                    const char *current_path = glob_result.gl_pathv[i];
                    if (!stat(current_path, &info)) {
                        if (!(info.st_mode & S_IFDIR)) {
                            if(n >= offset)
                                result.emplace_back(std::string(current_path));
                            n++;
                            if(result.size() >= limit) {
                                globfree(&glob_result);
                                return result;
                            }
                        }
                    }
                    break;
                }
                case sfDirectoriesOnly: {
                    const char *current_path = glob_result.gl_pathv[i];
                    if (!stat(current_path, &info)) {
                        if (info.st_mode & S_IFDIR) {
                            if(n >= offset)
                                result.emplace_back(std::string(current_path));
                            n++;
                            if(result.size() >= limit) {
                                globfree(&glob_result);
                                return result;
                            }
                        }
                    }
                    break;
                }
                default:
                    globfree(&glob_result);
                    return result;
            }
        }

        SPRINTF(Status, "%d files found", (int)glob_result.gl_pathc);
    }
    globfree(&glob_result);
#endif
    return result;
}
//------------------------------------------------------------------------------
