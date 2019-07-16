#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#include <common/defs.h>
#include <common/macro.h>

typedef struct Log {
    enum raLogMode {
        ralmSilent = 0,
        ralmExc,
        ralmErr,
        ralmWarn,
        ralmLog,
        ralmDebug,
        ralmDetails,

        ralmCount
    };
    Log(const raLogMode lm) : ralm(lm) {}
    void exc(const char *cStrTemplate, ...);
    void err(const char *cStrTemplate, ...);
    void warn(const char *cStrTemplate, ...);
    void log(const char *cStrTemplate, ...);
    void dbg(const char *cStrTemplate, ...);
    void dtl(const char *cStrTemplate, ...);
private:
    raLogMode ralm;
    const char *cExc = "EXCEPTION: %s\n";
    const char *cErr = "ERROR: %s\n";
    const char *cWarn = "WARNING: %s\n";
    const char *cLog = "LOG: %s\n";
    const char *cDebug = "DEBUG: %s\n";
    const char *cDetails = "DETAILS: %s\n";
} *HLog, *PLog;

extern Log logger;

