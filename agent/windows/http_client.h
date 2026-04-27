#pragma once
/*
 * http_client.h - WinHTTP REST client for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Thread-safe WinHTTP wrapper. Each HttpPost call creates its own
 * request handle from a shared session/connection (WinHTTP design).
 * Retries 3x with 1/2/4s backoff on network errors.
 */

#include <windows.h>

/* Opaque HTTP client handle */
typedef struct _HTTP_CLIENT HTTP_CLIENT;

/*
 * HttpClientCreate - allocate and initialize HTTP client.
 *
 * base_url:     "http://host:port" or "https://host:port" — no trailing slash.
 * bearer_token: raw JWT string (no "Bearer " prefix).
 * tls_verify:   1 = verify TLS cert (production), 0 = ignore cert errors (dev).
 *
 * Returns NULL on failure. Caller must call HttpClientDestroy when done.
 */
HTTP_CLIENT* HttpClientCreate(const char* base_url,
                               const char* bearer_token,
                               BOOL        tls_verify);

/* Free all resources. Safe to call with NULL. */
void HttpClientDestroy(HTTP_CLIENT* client);

/*
 * HttpPost - POST a JSON body to a path.
 *
 * path:          e.g. "/api/v1/logs/ingest"
 * json_body:     null-terminated UTF-8 JSON
 * response_buf:  caller buffer for response body (may be NULL)
 * response_size: size of response_buf in bytes (0 if NULL)
 * status_code:   receives HTTP status (or 0 on network error) — may be NULL
 *
 * Returns TRUE if HTTP 2xx received.
 * Retries up to 3 times with 1/2/4s backoff on WinHTTP network errors.
 * Does NOT retry on HTTP 4xx/5xx (server errors are not network errors).
 */
BOOL HttpPost(HTTP_CLIENT* client,
              const char*  path,
              const char*  json_body,
              char*        response_buf,
              size_t       response_size,
              int*         status_code);
