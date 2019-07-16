#ifndef _FSHELPER_H_
#define _FSHELPER_H_

#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <string.h>
#include <list>

#ifdef _WIN32
//#include <Windows.h>
#else
#include <fcntl.h>
#include <unistd.h>
#include <sys/mman.h>
#include <glob.h>
#include <sys/stat.h>
#endif

#include <common/defs.h>
#include <common/macro.h>
#include "log.h"

bool dirExists(const char *path);
bool fileExists(const char *path);

typedef enum {
    sfInvalid = -1,
    sfAll = 0,
    sfFilesOnly,
    sfDirectoriesOnly,

    sfCount
} SearchFlags;
unsigned char *loadBufferFromFile(const char *cFileName,
        size_t &FileSz,
        char *Status = nullptr,
        size_t StatusSz = 0);
bool saveBufferToFile(const char *cFileName,
        const unsigned char *Blob,
        size_t cBlobSz,
        char *Status = nullptr,
        size_t StatusSz = 0);

size_t dir_count(const std::string &dir);
std::list<std::string> list_directory(const std::string &pattern,
                            const std::string &dir,
                            SearchFlags sf = sfAll,
                            size_t offset = 0,
                            size_t limit = (~(size_t)0),
                            char *Status = nullptr,
                            size_t StatusSz = 0);

#endif
