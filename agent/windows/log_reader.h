#pragma once
/*
 * log_reader.h - File log reader with offset persistence for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Tails configured log files from last-read byte offset.
 * Offsets persisted in an INI file. Detects log rotation (file shrink).
 * Severity inferred from line content keywords.
 */

#include <windows.h>

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define LR_MAX_FILES    32
#define LR_MAX_PATH     260
#define LR_MAX_LINE     10000
#define LR_MAX_MESSAGE  5000
#define LR_MAX_BATCH    100

/* ------------------------------------------------------------------ */
/*  Data types                                                        */
/* ------------------------------------------------------------------ */

typedef struct {
    char source[256];
    char event_type[64];           /* always "file_log"                */
    char message[LR_MAX_MESSAGE];  /* line text, truncated             */
    char raw_log[LR_MAX_LINE];     /* full line, truncated             */
    char severity[16];             /* "critical","error","warning",    */
                                   /* "info","debug"                   */
    char event_timestamp[32];      /* ISO8601 UTC of collection time   */
    int  endpoint_id;
    char file_path[LR_MAX_PATH];   /* UTF-8 path                       */
} LRLogEntry;

typedef struct {
    LRLogEntry entries[LR_MAX_BATCH];
    int        count;
} LRLogBatch;

typedef struct {
    WCHAR paths[LR_MAX_FILES][LR_MAX_PATH]; /* files to monitor        */
    int   count;                             /* number of valid paths   */
    WCHAR offset_file[LR_MAX_PATH];          /* INI file for offsets    */
} LogReaderConfig;

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/*
 * ReadNewLogs - collect unread lines since last offset.
 *
 * Reads up to LR_MAX_BATCH entries across all files.
 * Updates offsets in cfg->offset_file after each file.
 * Returns TRUE always (batch->count may be 0 if nothing new).
 */
BOOL ReadNewLogs(const LogReaderConfig* cfg,
                 int                    endpoint_id,
                 LRLogBatch*            batch);

/*
 * InferSeverity - infer severity from line content (case-insensitive keyword scan).
 * Priority: critical > error > warning > debug > info (default).
 * Returns a pointer to a static string literal; do not free.
 */
const char* InferSeverity(const char* line);
