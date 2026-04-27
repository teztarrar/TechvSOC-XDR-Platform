/*
 * json_builder.c - Stack-allocated JSON serializer for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Zero allocations. Write into caller-provided buffer.
 * Graceful truncation — never overflows, always null-terminates.
 */

#pragma comment(lib, "strsafe.lib")

#include <windows.h>
#include <strsafe.h>
#include <string.h>
#include "json_builder.h"

/* ------------------------------------------------------------------ */
/*  Internal append helpers                                           */
/* ------------------------------------------------------------------ */

/*
 * JAppend - append raw bytes into the builder's buffer.
 * Never writes past cap-1; never NUL-terminates mid-stream.
 * Silently truncates when full.
 */
static void JAppend(JsonBuilder* b, const char* s, size_t n)
{
    size_t avail = (b->len < b->cap - 1) ? (b->cap - 1 - b->len) : 0;
    if (avail == 0) return;
    if (n > avail) n = avail;
    memcpy(b->buf + b->len, s, n);
    b->len += n;
}

/* JAppendStr - append a null-terminated string. */
static void JAppendStr(JsonBuilder* b, const char* s)
{
    JAppend(b, s, strlen(s));
}

/*
 * JSep - write a comma separator before the next item at the current
 * depth, then mark the depth as having had at least one item.
 */
static void JSep(JsonBuilder* b)
{
    if (!b->first[b->depth]) {
        JAppendStr(b, ",");
    }
    b->first[b->depth] = FALSE;
}

/* ------------------------------------------------------------------ */
/*  JsonInit                                                          */
/* ------------------------------------------------------------------ */

void JsonInit(JsonBuilder* b, char* buf, size_t cap)
{
    memset(b, 0, sizeof(*b));
    b->buf  = buf;
    b->cap  = cap;
    b->len  = 0;
    b->depth = 0;
    b->first[0]    = TRUE;
    b->in_array[0] = FALSE;

    /* Ensure the buffer starts empty / safe */
    if (buf && cap > 0) {
        buf[0] = '\0';
    }
}

/* ------------------------------------------------------------------ */
/*  Object / array begin + end                                        */
/* ------------------------------------------------------------------ */

void JsonObjectBegin(JsonBuilder* b)
{
    JAppendStr(b, "{");
    b->depth++;
    if (b->depth < JSON_MAX_DEPTH) {
        b->first[b->depth]    = TRUE;
        b->in_array[b->depth] = FALSE;
    }
}

void JsonObjectEnd(JsonBuilder* b)
{
    if (b->depth > 0) {
        b->depth--;
    }
    JAppendStr(b, "}");
}

/* ------------------------------------------------------------------ */

void JsonNestedObjectBegin(JsonBuilder* b, const char* key)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":{");
    b->depth++;
    if (b->depth < JSON_MAX_DEPTH) {
        b->first[b->depth]    = TRUE;
        b->in_array[b->depth] = FALSE;
    }
}

void JsonNestedObjectEnd(JsonBuilder* b)
{
    if (b->depth > 0) {
        b->depth--;
    }
    JAppendStr(b, "}");
}

/* ------------------------------------------------------------------ */

void JsonArrayBegin(JsonBuilder* b, const char* key)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":[");
    b->depth++;
    if (b->depth < JSON_MAX_DEPTH) {
        b->first[b->depth]    = TRUE;
        b->in_array[b->depth] = TRUE;
    }
}

void JsonArrayEnd(JsonBuilder* b)
{
    if (b->depth > 0) {
        b->depth--;
    }
    JAppendStr(b, "]");
}

/* ------------------------------------------------------------------ */

void JsonAnonObjectBegin(JsonBuilder* b)
{
    /* Emit separator at the parent array depth, then open brace */
    JSep(b);
    JAppendStr(b, "{");
    b->depth++;
    if (b->depth < JSON_MAX_DEPTH) {
        b->first[b->depth]    = TRUE;
        b->in_array[b->depth] = FALSE;
    }
}

void JsonAnonObjectEnd(JsonBuilder* b)
{
    if (b->depth > 0) {
        b->depth--;
    }
    JAppendStr(b, "}");
}

/* ------------------------------------------------------------------ */
/*  JsonStr - named string field with full JSON escaping              */
/* ------------------------------------------------------------------ */

void JsonStr(JsonBuilder* b, const char* key, const char* val)
{
    JSep(b);

    /* Write "key":" */
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":\"");

    /* Write escaped val */
    if (val) {
        for (const char* p = val; *p; p++) {
            unsigned char c = (unsigned char)*p;
            if (c == '"') {
                JAppend(b, "\\\"", 2);
            } else if (c == '\\') {
                JAppend(b, "\\\\", 2);
            } else if (c == '\n') {
                JAppend(b, "\\n",  2);
            } else if (c == '\r') {
                JAppend(b, "\\r",  2);
            } else if (c == '\t') {
                JAppend(b, "\\t",  2);
            } else if (c < 0x20) {
                /* Control characters: \uXXXX */
                char esc[7];
                StringCchPrintfA(esc, sizeof(esc), "\\u%04X", (unsigned int)c);
                JAppendStr(b, esc);
            } else {
                JAppend(b, (const char*)&c, 1);
            }
        }
    }

    JAppendStr(b, "\"");
}

/* ------------------------------------------------------------------ */
/*  JsonStrW - named wide-string field                                */
/* ------------------------------------------------------------------ */

void JsonStrW(JsonBuilder* b, const char* key, const WCHAR* val)
{
    if (!val) {
        /* Emit a null for a missing wide string */
        JsonNull(b, key);
        return;
    }

    /* Convert WCHAR* to UTF-8 in a stack buffer, then delegate to JsonStr */
    char tmp[8192];
    tmp[0] = '\0';
    WideCharToMultiByte(CP_UTF8, 0, val, -1, tmp, (int)sizeof(tmp), NULL, NULL);
    /* WideCharToMultiByte always null-terminates when the buffer is large
       enough; if it truncates, the last byte stays valid because we
       initialized tmp[0] and the function adds a NUL as far as possible. */
    JsonStr(b, key, tmp);
}

/* ------------------------------------------------------------------ */
/*  JsonInt                                                           */
/* ------------------------------------------------------------------ */

void JsonInt(JsonBuilder* b, const char* key, long long val)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":");

    /* Format integer without quotes */
    char tmp[64];
    StringCchPrintfA(tmp, sizeof(tmp), "%I64d", val);
    JAppendStr(b, tmp);
}

/* ------------------------------------------------------------------ */
/*  JsonDouble                                                        */
/* ------------------------------------------------------------------ */

void JsonDouble(JsonBuilder* b, const char* key, double val, int prec)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":");

    /* Build a format string like "%.2f", then format the value */
    char fmt[16];
    char tmp[64];
    StringCchPrintfA(fmt, sizeof(fmt), "%%.%df", prec);
    StringCchPrintfA(tmp, sizeof(tmp), fmt, val);
    JAppendStr(b, tmp);
}

/* ------------------------------------------------------------------ */
/*  JsonBool                                                          */
/* ------------------------------------------------------------------ */

void JsonBool(JsonBuilder* b, const char* key, BOOL val)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":");
    JAppendStr(b, val ? "true" : "false");
}

/* ------------------------------------------------------------------ */
/*  JsonNull                                                          */
/* ------------------------------------------------------------------ */

void JsonNull(JsonBuilder* b, const char* key)
{
    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":null");
}

/* ------------------------------------------------------------------ */
/*  JsonTimestampNow                                                  */
/* ------------------------------------------------------------------ */

void JsonTimestampNow(JsonBuilder* b, const char* key)
{
    SYSTEMTIME st;
    GetSystemTime(&st);

    char ts[32];
    StringCchPrintfA(ts, sizeof(ts),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        (int)st.wYear,  (int)st.wMonth,       (int)st.wDay,
        (int)st.wHour,  (int)st.wMinute,      (int)st.wSecond,
        (int)st.wMilliseconds);

    JSep(b);
    JAppendStr(b, "\"");
    JAppendStr(b, key);
    JAppendStr(b, "\":\"");
    JAppendStr(b, ts);
    JAppendStr(b, "\"");
}

/* ------------------------------------------------------------------ */
/*  JsonFinish                                                        */
/* ------------------------------------------------------------------ */

const char* JsonFinish(JsonBuilder* b)
{
    if (b->cap > 0) {
        b->buf[b->len] = '\0';
    }
    return b->buf;
}
