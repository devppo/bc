#include "common/log.h"

Log logger(LOG_LEVEL);

void Log::exc(const char *cStrTemplate, ...) {
    if(ralm < ralmExc) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cExc, Buffer);
}

void Log::err(const char *cStrTemplate, ...) {
    if(ralm < ralmErr) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cErr, Buffer);
}

void Log::warn(const char *cStrTemplate, ...) {
    if(ralm < ralmWarn) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cWarn, Buffer);
}

void Log::dbg(const char *cStrTemplate, ...) {
    if(ralm < ralmDebug) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cDebug, Buffer);
}

void Log::log(const char *cStrTemplate, ...) {
    if(ralm < ralmLog) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cLog, Buffer);
}

void Log::dtl(const char *cStrTemplate, ...) {
    if(ralm < ralmDetails) return;
    char Buffer[0x400] = {'\0'};
    va_list args;
    va_start(args, cStrTemplate);
    vsprintf(Buffer, cStrTemplate, args);
    va_end(args);
    printf(cDetails, Buffer);
}
