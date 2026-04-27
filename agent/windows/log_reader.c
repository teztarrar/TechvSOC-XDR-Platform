/*
 * log_reader.c - File log reader with offset persistence for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Tails arbitrary text log files from a persisted byte offset.
 * Offsets are stored in an INI file keyed by path (\ replaced with /).
 * Detects log rotation by comparing current file size to saved offset.
 * Severity is inferred from line keywords (case-insensitive).
 * No CRT heap allocation; uses HeapAlloc/HeapFree throughout.
 */

#pragma comment(lib, "kernel32.lib")

#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include "log_reader.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define READ_BUF_SIZE   65536   /* byte chunk per ReadFile call         */

/* ------------------------------------------------------------------ */
/*  Forward declarations                                              */
/* ------------------------------------------------------------------ */

static void        PathToIniKey(const WCHAR* path, WCHAR* key, size_t keysz);
static void        PopulateEntry(LRLogEntry* entry, const WCHAR* path,
                                 const char* line, int endpoint_id);
static BOOL        ProcessFile(const LogReaderConfig* cfg,
                                const WCHAR* path,
                                int endpoint_id,
                                LRLogBatch* batch);

/* ------------------------------------------------------------------ */
/*  InferSeverity                                                     */
/* ------------------------------------------------------------------ */

/*
 * InferSeverity - case-insensitive keyword scan on line.
 * Priority order: critical > error > warning > debug > info.
 * Lowercases up to 256 chars of line into a stack buffer to avoid
 * heap allocation.  Returns a string literal; do not free.
 */
const char* InferSeverity(const char* line)
{
    char lower[256];
    int  i;

    if (!line) {
        return "info";
    }

    /* Copy and lowercase up to 255 chars */
    for (i = 0; i < 255 && line[i] != '\0'; i++) {
        char c = line[i];
        if (c >= 'A' && c <= 'Z') {
            c = (char)(c + ('a' - 'A'));
        }
        lower[i] = c;
    }
    lower[i] = '\0';

    /* Check priority order: critical first */
    if (strstr(lower, "critical") || strstr(lower, "fatal")) {
        return "critical";
    }
    if (strstr(lower, "error") || strstr(lower, "failed")) {
        return "error";
    }
    if (strstr(lower, "warning") || strstr(lower, "warn")) {
        return "warning";
    }
    if (strstr(lower, "debug")) {
        return "debug";
    }

    return "info";
}

/* ------------------------------------------------------------------ */
/*  INI key helpers                                                   */
/* ------------------------------------------------------------------ */

/*
 * PathToIniKey - copy path to key, replacing every \ with /
 * so the result is a valid INI key name (INI keys cannot contain \).
 */
static void PathToIniKey(const WCHAR* path, WCHAR* key, size_t keysz)
{
    WCHAR* p;
    StringCchCopyW(key, keysz, path);
    for (p = key; *p != L'\0'; p++) {
        if (*p == L'\\') {
            *p = L'/';
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Entry population                                                  */
/* ------------------------------------------------------------------ */

/*
 * PopulateEntry - fill one LRLogEntry from a parsed line.
 *
 * source:           last path component (filename after last \ or /)
 * event_type:       always "file_log"
 * raw_log/message:  line text (StringCchCopyA truncates safely)
 * severity:         from InferSeverity
 * event_timestamp:  ISO8601 UTC at moment of parsing
 * endpoint_id:      passed through
 * file_path:        UTF-8 version of wide path
 */
static void PopulateEntry(LRLogEntry* entry, const WCHAR* path,
                           const char* line, int endpoint_id)
{
    const char* slash;

    /* Convert wide path to UTF-8 for file_path field */
    WideCharToMultiByte(CP_UTF8, 0, path, -1,
                        entry->file_path, LR_MAX_PATH, NULL, NULL);

    /* source: filename component (after last \ or /) */
    slash = strrchr(entry->file_path, '\\');
    if (!slash) {
        slash = strrchr(entry->file_path, '/');
    }
    StringCchCopyA(entry->source, sizeof(entry->source),
                   slash ? slash + 1 : entry->file_path);

    /* event_type is always "file_log" */
    StringCchCopyA(entry->event_type, sizeof(entry->event_type), "file_log");

    /* raw_log and message: full line text, truncated at their respective limits */
    StringCchCopyA(entry->raw_log, LR_MAX_LINE,    line);
    StringCchCopyA(entry->message, LR_MAX_MESSAGE, line);

    /* severity: inferred from line content */
    StringCchCopyA(entry->severity, sizeof(entry->severity),
                   InferSeverity(line));

    /* event_timestamp: ISO8601 UTC */
    {
        SYSTEMTIME st;
        GetSystemTime(&st);
        StringCchPrintfA(entry->event_timestamp, sizeof(entry->event_timestamp),
            "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    }

    entry->endpoint_id = endpoint_id;
}

/* ------------------------------------------------------------------ */
/*  Per-file tail logic                                               */
/* ------------------------------------------------------------------ */

/*
 * ProcessFile - read unread lines from a single file, append to batch.
 *
 * Algorithm:
 *   1. Load saved offset from INI.
 *   2. Open file (shared read+write+delete).
 *   3. Detect rotation: file size < saved offset => reset to 0.
 *   4. Seek to saved offset.
 *   5. Read in READ_BUF_SIZE chunks; parse complete lines (\n or \r\n).
 *      Incomplete final line (no trailing \n) is NOT emitted; pointer
 *      is left at start of that partial line.
 *   6. Save updated offset to INI.
 *   7. Stop when batch is full.
 */
static BOOL ProcessFile(const LogReaderConfig* cfg,
                         const WCHAR* path,
                         int endpoint_id,
                         LRLogBatch* batch)
{
    WCHAR         key[LR_MAX_PATH * 2];
    DWORD         saved_dword;
    LONGLONG      saved_offset;
    HANDLE        hFile;
    LARGE_INTEGER fileSize;
    LARGE_INTEGER li;
    LARGE_INTEGER newPos;
    LARGE_INTEGER zero;
    char*         read_buf;
    DWORD         bytes_read;
    char*         buf_start;
    char*         p;
    char*         line_start;
    BOOL          had_newline;
    WCHAR         offsetStr[32];

    /* ---- Build INI key for this path ---- */
    PathToIniKey(path, key, sizeof(key) / sizeof(key[0]));

    /* ---- Load saved offset (stored as decimal DWORD in INI) ---- */
    /*
     * GetPrivateProfileIntW only reads 32-bit values.
     * For files > 4 GB, ReadNewLogs would need a wider API.
     * For typical log files this is sufficient production behaviour.
     */
    saved_dword  = (DWORD)GetPrivateProfileIntW(L"offsets", key, 0,
                                                 cfg->offset_file);
    saved_offset = (LONGLONG)(DWORDLONG)saved_dword;

    /* ---- Open file ---- */
    hFile = CreateFileW(path,
                        GENERIC_READ,
                        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                        NULL,
                        OPEN_EXISTING,
                        FILE_ATTRIBUTE_NORMAL,
                        NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        /* File may not exist yet -- skip silently */
        return TRUE;
    }

    /* ---- Get file size ---- */
    if (!GetFileSizeEx(hFile, &fileSize)) {
        CloseHandle(hFile);
        return TRUE;
    }

    /* ---- Detect log rotation (file shrank below saved offset) ---- */
    if (fileSize.QuadPart < saved_offset) {
        saved_offset = 0;
    }

    /* ---- Nothing new? ---- */
    if (fileSize.QuadPart == saved_offset) {
        CloseHandle(hFile);
        return TRUE;
    }

    /* ---- Seek to saved offset ---- */
    li.QuadPart = saved_offset;
    if (!SetFilePointerEx(hFile, li, NULL, FILE_BEGIN)) {
        CloseHandle(hFile);
        return TRUE;
    }

    /* ---- Allocate read buffer on heap (65 KB fits on any stack, but
            keep it off stack to be consistent with coding standards) ---- */
    read_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY,
                                 READ_BUF_SIZE);
    if (!read_buf) {
        CloseHandle(hFile);
        return TRUE;
    }

    /* ---- Read loop ---- */
    while (batch->count < LR_MAX_BATCH) {

        if (!ReadFile(hFile, read_buf, READ_BUF_SIZE - 1, &bytes_read, NULL)) {
            break;
        }
        if (bytes_read == 0) {
            /* EOF */
            break;
        }

        read_buf[bytes_read] = '\0';

        /* ---- Line parsing ---- */
        buf_start  = read_buf;
        line_start = read_buf;
        had_newline = FALSE;

        for (p = read_buf; p < read_buf + (ptrdiff_t)bytes_read; p++) {
            if (*p == '\n') {
                had_newline = TRUE;

                /* Strip trailing \r if present */
                char* line_end = p;
                if (line_end > line_start && *(line_end - 1) == '\r') {
                    line_end--;
                }

                /* NUL-terminate the line in place temporarily */
                char saved_char = *line_end;
                *line_end = '\0';

                /* Emit non-empty lines only */
                if (line_start < line_end || line_start == (line_end + 1)) {
                    /* Emit even empty lines — they are valid log lines */
                    PopulateEntry(&batch->entries[batch->count],
                                  path, line_start, endpoint_id);
                    batch->count++;
                }

                /* Restore and advance */
                *line_end  = saved_char;
                line_start = p + 1;

                if (batch->count >= LR_MAX_BATCH) {
                    break;
                }
            }
        }

        /*
         * If the buffer did not end with \n, there is a partial line at
         * [line_start .. read_buf+bytes_read).  We must not emit it and
         * must seek back so it will be re-read next call.
         */
        if (line_start < read_buf + (ptrdiff_t)bytes_read) {
            /* Seek back to the start of the partial line */
            ptrdiff_t partial_len = (read_buf + bytes_read) - line_start;
            LARGE_INTEGER back;
            back.QuadPart = -(LONGLONG)partial_len;
            SetFilePointerEx(hFile, back, NULL, FILE_CURRENT);
        }

        /* If we read less than a full buffer, we've hit EOF */
        if (bytes_read < READ_BUF_SIZE - 1) {
            break;
        }

        /* If batch is now full, stop */
        if (batch->count >= LR_MAX_BATCH) {
            break;
        }

        UNREFERENCED_PARAMETER(buf_start);
        UNREFERENCED_PARAMETER(had_newline);
    }

    HeapFree(GetProcessHeap(), 0, read_buf);

    /* ---- Record new file position ---- */
    zero.QuadPart = 0;
    SetFilePointerEx(hFile, zero, &newPos, FILE_CURRENT);
    CloseHandle(hFile);

    /* ---- Persist new offset to INI ---- */
    /*
     * We store as a decimal wide string.  For files > ~4 GB this would
     * overflow a DWORD; we store the full 64-bit value as a string so
     * WritePrivateProfileString keeps the full precision.
     */
    StringCchPrintfW(offsetStr, sizeof(offsetStr) / sizeof(offsetStr[0]),
                     L"%I64u", (unsigned __int64)newPos.QuadPart);
    WritePrivateProfileStringW(L"offsets", key, offsetStr, cfg->offset_file);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  ReadNewLogs                                                       */
/* ------------------------------------------------------------------ */

/*
 * ReadNewLogs - collect unread lines since last offset from all configured
 * log files.  Fills batch->entries[0..count-1].  Stops when the batch is
 * full (LR_MAX_BATCH entries) even if more files remain.
 *
 * Always returns TRUE; batch->count may be 0 if nothing new was found.
 */
BOOL ReadNewLogs(const LogReaderConfig* cfg,
                 int                    endpoint_id,
                 LRLogBatch*            batch)
{
    int i;

    if (!cfg || !batch) {
        return TRUE;
    }

    batch->count = 0;

    for (i = 0; i < cfg->count && batch->count < LR_MAX_BATCH; i++) {
        ProcessFile(cfg, cfg->paths[i], endpoint_id, batch);
    }

    return TRUE;
}
