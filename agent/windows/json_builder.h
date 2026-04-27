#pragma once
/*
 * json_builder.h - Stack-allocated JSON serializer for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Zero allocations. Write into caller-provided buffer.
 * Graceful truncation — never overflows, always null-terminates.
 */

#include <windows.h>

#define JSON_MAX_DEPTH 16

typedef struct {
    char*  buf;                       /* caller-owned output buffer        */
    size_t cap;                       /* buffer capacity in bytes          */
    size_t len;                       /* bytes written so far (excl. NUL)  */
    int    depth;                     /* current nesting depth             */
    BOOL   first[JSON_MAX_DEPTH];     /* TRUE if no item written at depth  */
    BOOL   in_array[JSON_MAX_DEPTH];  /* TRUE if this depth is an array    */
} JsonBuilder;

/* Initialize. buf must remain valid for the lifetime of the builder. */
void        JsonInit(JsonBuilder* b, char* buf, size_t cap);

/* Top-level object begin/end */
void        JsonObjectBegin(JsonBuilder* b);
void        JsonObjectEnd(JsonBuilder* b);

/* Named nested object: "key":{...} */
void        JsonNestedObjectBegin(JsonBuilder* b, const char* key);
void        JsonNestedObjectEnd(JsonBuilder* b);

/* Named array field: "key":[...] */
void        JsonArrayBegin(JsonBuilder* b, const char* key);
void        JsonArrayEnd(JsonBuilder* b);

/* Anonymous object element inside array: {...} */
void        JsonAnonObjectBegin(JsonBuilder* b);
void        JsonAnonObjectEnd(JsonBuilder* b);

/* Named string field. val is UTF-8. Escapes: " \ \n \r \t U+0000-U+001F */
void        JsonStr(JsonBuilder* b, const char* key, const char* val);

/* Named wide-string field. Converts WCHAR* to UTF-8 inline, then writes. */
void        JsonStrW(JsonBuilder* b, const char* key, const WCHAR* val);

/* Numeric / boolean / null fields */
void        JsonInt(JsonBuilder* b, const char* key, long long val);
void        JsonDouble(JsonBuilder* b, const char* key, double val, int prec);
void        JsonBool(JsonBuilder* b, const char* key, BOOL val);
void        JsonNull(JsonBuilder* b, const char* key);

/* UTC timestamp field: "key":"2024-01-15T12:34:56.000Z" */
void        JsonTimestampNow(JsonBuilder* b, const char* key);

/* Null-terminate buffer and return pointer to it (always valid). */
const char* JsonFinish(JsonBuilder* b);
