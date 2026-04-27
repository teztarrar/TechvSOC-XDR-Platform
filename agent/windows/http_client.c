/*
 * http_client.c - WinHTTP REST client for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Thread-safe WinHTTP wrapper. Each HttpPost call creates its own
 * request handle from a shared session/connection (WinHTTP design).
 * Retries 3x with 1/2/4s backoff on network errors.
 */

#pragma comment(lib, "winhttp.lib")

#include <windows.h>
#include <winhttp.h>
#include <strsafe.h>
#include <string.h>
#include "http_client.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define HTTP_CONNECT_TIMEOUT_MS     30000
#define HTTP_SEND_TIMEOUT_MS        30000
#define HTTP_RECEIVE_TIMEOUT_MS     30000
#define HTTP_MAX_RETRIES            3
#define HTTP_BODY_READ_CHUNK        4096
#define HTTP_TOKEN_MAX              512
#define HTTP_HOST_MAX               256
#define HTTP_HEADER_MAX             1024

/* WINHTTP_OPTION_SECURITY_FLAGS value to bypass all TLS cert checks */
#define SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS_VALUE  \
    ( SECURITY_FLAG_IGNORE_UNKNOWN_CA          |    \
      SECURITY_FLAG_IGNORE_CERT_DATE_INVALID   |    \
      SECURITY_FLAG_IGNORE_CERT_CN_INVALID     |    \
      SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE )

/* ------------------------------------------------------------------ */
/*  Struct definition                                                 */
/* ------------------------------------------------------------------ */

typedef struct _HTTP_CLIENT {
    HINTERNET   session;         /* WinHttpOpen handle      */
    HINTERNET   connection;      /* WinHttpConnect handle   */
    WCHAR       host[HTTP_HOST_MAX]; /* parsed from base_url    */
    INTERNET_PORT port;          /* parsed port number      */
    BOOL        is_https;
    BOOL        tls_verify;
    char        token[HTTP_TOKEN_MAX]; /* bearer token       */
} HTTP_CLIENT;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                              */
/* ------------------------------------------------------------------ */

static BOOL ParseBaseUrl(const char* base_url,
                          WCHAR*      host_out,
                          DWORD       host_cap,
                          INTERNET_PORT* port_out,
                          BOOL*       is_https_out);

/* ------------------------------------------------------------------ */
/*  URL parsing helper                                                */
/* ------------------------------------------------------------------ */

/*
 * ParseBaseUrl - parse "http[s]://host[:port]" into components.
 *
 * Fills host_out, port_out, is_https_out.
 * Returns TRUE on success.
 */
static BOOL ParseBaseUrl(const char* base_url,
                          WCHAR*      host_out,
                          DWORD       host_cap,
                          INTERNET_PORT* port_out,
                          BOOL*       is_https_out)
{
    if (!base_url || !host_out || !port_out || !is_https_out) {
        return FALSE;
    }

    const char* p = base_url;

    /* Detect scheme */
    if (_strnicmp(p, "https://", 8) == 0) {
        *is_https_out = TRUE;
        *port_out     = INTERNET_DEFAULT_HTTPS_PORT;
        p += 8;
    } else if (_strnicmp(p, "http://", 7) == 0) {
        *is_https_out = FALSE;
        *port_out     = INTERNET_DEFAULT_HTTP_PORT;
        p += 7;
    } else {
        /* No scheme: assume http */
        *is_https_out = FALSE;
        *port_out     = INTERNET_DEFAULT_HTTP_PORT;
    }

    /* Find optional colon for port, or end of string */
    const char* colon = strchr(p, ':');
    const char* slash = strchr(p, '/');

    size_t host_len;
    if (colon && (!slash || colon < slash)) {
        /* host:port */
        host_len = (size_t)(colon - p);

        /* Parse port number */
        long port_val = strtol(colon + 1, NULL, 10);
        if (port_val > 0 && port_val <= 65535) {
            *port_out = (INTERNET_PORT)port_val;
        }
    } else if (slash) {
        /* host/path — no port */
        host_len = (size_t)(slash - p);
    } else {
        /* host only */
        host_len = strlen(p);
    }

    if (host_len == 0 || host_len >= HTTP_HOST_MAX - 1) {
        return FALSE;
    }

    /* Copy host bytes into a narrow temp buffer, then widen */
    char host_narrow[HTTP_HOST_MAX];
    memcpy(host_narrow, p, host_len);
    host_narrow[host_len] = '\0';

    int wlen = MultiByteToWideChar(CP_UTF8, 0, host_narrow, -1,
                                    host_out, (int)host_cap);
    return (wlen > 0);
}

/* ------------------------------------------------------------------ */
/*  HttpClientCreate                                                  */
/* ------------------------------------------------------------------ */

HTTP_CLIENT* HttpClientCreate(const char* base_url,
                               const char* bearer_token,
                               BOOL        tls_verify)
{
    if (!base_url) {
        return NULL;
    }

    /* Parse URL components before allocating anything */
    WCHAR         host[HTTP_HOST_MAX];
    INTERNET_PORT port;
    BOOL          is_https;

    if (!ParseBaseUrl(base_url, host, HTTP_HOST_MAX, &port, &is_https)) {
        return NULL;
    }

    /* Open WinHTTP session */
    HINTERNET session = WinHttpOpen(
        L"TechvSOC-Agent/2.0",
        WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
        WINHTTP_NO_PROXY_NAME,
        WINHTTP_NO_PROXY_BYPASS,
        0);

    if (!session) {
        return NULL;
    }

    /* Set connect / send / receive timeouts to 30 s */
    DWORD timeout = HTTP_CONNECT_TIMEOUT_MS;
    WinHttpSetOption(session, WINHTTP_OPTION_CONNECT_TIMEOUT,
                     &timeout, sizeof(DWORD));

    timeout = HTTP_SEND_TIMEOUT_MS;
    WinHttpSetOption(session, WINHTTP_OPTION_SEND_TIMEOUT,
                     &timeout, sizeof(DWORD));

    timeout = HTTP_RECEIVE_TIMEOUT_MS;
    WinHttpSetOption(session, WINHTTP_OPTION_RECEIVE_TIMEOUT,
                     &timeout, sizeof(DWORD));

    /* Open connection to host:port */
    HINTERNET connection = WinHttpConnect(session, host, port, 0);
    if (!connection) {
        WinHttpCloseHandle(session);
        return NULL;
    }

    /* Allocate and populate the client struct */
    HTTP_CLIENT* client = (HTTP_CLIENT*)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(HTTP_CLIENT));
    if (!client) {
        WinHttpCloseHandle(connection);
        WinHttpCloseHandle(session);
        return NULL;
    }

    client->session    = session;
    client->connection = connection;
    client->port       = port;
    client->is_https   = is_https;
    client->tls_verify = tls_verify;

    /* Copy host (already WCHAR) */
    StringCchCopyW(client->host, HTTP_HOST_MAX, host);

    /* Copy bearer token (narrow) */
    if (bearer_token) {
        StringCchCopyA(client->token, HTTP_TOKEN_MAX, bearer_token);
    }

    return client;
}

/* ------------------------------------------------------------------ */
/*  HttpClientDestroy                                                 */
/* ------------------------------------------------------------------ */

void HttpClientDestroy(HTTP_CLIENT* client)
{
    if (!client) {
        return;
    }

    if (client->connection) {
        WinHttpCloseHandle(client->connection);
        client->connection = NULL;
    }
    if (client->session) {
        WinHttpCloseHandle(client->session);
        client->session = NULL;
    }

    HeapFree(GetProcessHeap(), 0, client);
}

/* ------------------------------------------------------------------ */
/*  HttpPost                                                          */
/* ------------------------------------------------------------------ */

BOOL HttpPost(HTTP_CLIENT* client,
              const char*  path,
              const char*  json_body,
              char*        response_buf,
              size_t       response_size,
              int*         status_code)
{
    if (!client || !path || !json_body) {
        if (status_code) *status_code = 0;
        return FALSE;
    }

    /* Zero out caller's response buffer up front */
    if (response_buf && response_size > 0) {
        response_buf[0] = '\0';
    }
    if (status_code) {
        *status_code = 0;
    }

    /* Compute body length in bytes (UTF-8 octet count, not char count) */
    DWORD body_bytes = (DWORD)strlen(json_body);

    /* Convert narrow path to wide */
    WCHAR wpath[2048];
    {
        int wlen = MultiByteToWideChar(CP_UTF8, 0, path, -1,
                                        wpath, (int)(sizeof(wpath) / sizeof(WCHAR)));
        if (wlen <= 0) {
            return FALSE;
        }
    }

    /* Build Authorization header as wide string:
     * "Content-Type: application/json\r\nAuthorization: Bearer <token>\r\n"
     */
    WCHAR headers[HTTP_HEADER_MAX];
    {
        /* Widen the bearer token */
        WCHAR wtoken[HTTP_TOKEN_MAX];
        int wlen = MultiByteToWideChar(CP_UTF8, 0, client->token, -1,
                                        wtoken,
                                        (int)(sizeof(wtoken) / sizeof(WCHAR)));
        if (wlen <= 0) {
            wtoken[0] = L'\0';
        }

        StringCchPrintfW(headers, HTTP_HEADER_MAX,
            L"Content-Type: application/json\r\nAuthorization: Bearer %s\r\n",
            wtoken);
    }
    DWORD header_len = (DWORD)wcslen(headers);

    /* Retry loop: 0, 1, 2 attempts */
    for (int attempt = 0; attempt < HTTP_MAX_RETRIES; attempt++) {

        /* Backoff before second and third attempts */
        if (attempt == 1) {
            Sleep(1000);
        } else if (attempt == 2) {
            Sleep(2000);
        }

        /* Open a request handle */
        DWORD req_flags = client->is_https ? WINHTTP_FLAG_SECURE : 0;
        HINTERNET req = WinHttpOpenRequest(
            client->connection,
            L"POST",
            wpath,
            NULL,
            WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            req_flags);

        if (!req) {
            /* Can't even open request handle — retry */
            continue;
        }

        /* If HTTPS and TLS verify is disabled, ignore all cert errors */
        if (client->is_https && !client->tls_verify) {
            DWORD sec_flags = SECURITY_FLAG_IGNORE_ALL_CERT_ERRORS_VALUE;
            WinHttpSetOption(req, WINHTTP_OPTION_SECURITY_FLAGS,
                             &sec_flags, sizeof(DWORD));
        }

        /* Send the request */
        BOOL send_ok = WinHttpSendRequest(
            req,
            headers,
            header_len,
            (LPVOID)json_body,
            body_bytes,
            body_bytes,
            0);

        if (!send_ok) {
            /* Network error — close handle, retry */
            WinHttpCloseHandle(req);
            continue;
        }

        /* Wait for response */
        BOOL recv_ok = WinHttpReceiveResponse(req, NULL);
        if (!recv_ok) {
            /* Network error — close handle, retry */
            WinHttpCloseHandle(req);
            continue;
        }

        /* Query HTTP status code */
        DWORD http_status  = 0;
        DWORD status_size  = sizeof(DWORD);
        WinHttpQueryHeaders(
            req,
            WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
            WINHTTP_HEADER_NAME_BY_INDEX,
            &http_status,
            &status_size,
            WINHTTP_NO_HEADER_INDEX);

        if (status_code) {
            *status_code = (int)http_status;
        }

        /* Read response body if caller provided a buffer */
        if (response_buf && response_size > 1) {
            size_t   accumulated = 0;
            BOOL     body_ok     = TRUE;
            char*    chunk_buf   = (char*)HeapAlloc(
                GetProcessHeap(), HEAP_ZERO_MEMORY, HTTP_BODY_READ_CHUNK + 1);

            if (chunk_buf) {
                for (;;) {
                    DWORD bytes_read = 0;
                    BOOL  read_ok = WinHttpReadData(req, chunk_buf,
                                                     HTTP_BODY_READ_CHUNK,
                                                     &bytes_read);
                    if (!read_ok || bytes_read == 0) {
                        break;
                    }

                    /* Append to response_buf, leaving room for NUL */
                    size_t space = (response_size - 1) - accumulated;
                    if (space == 0) {
                        break;
                    }
                    size_t copy_n = (bytes_read < (DWORD)space)
                                        ? (size_t)bytes_read
                                        : space;
                    memcpy(response_buf + accumulated, chunk_buf, copy_n);
                    accumulated += copy_n;
                }
                HeapFree(GetProcessHeap(), 0, chunk_buf);
            }

            /* Always null-terminate */
            response_buf[accumulated] = '\0';
        }

        WinHttpCloseHandle(req);

        /* Evaluate result */
        if (http_status >= 200 && http_status < 300) {
            return TRUE;
        }

        /*
         * 4xx / 5xx are server-side errors — the network worked fine.
         * Do not retry; the server will not give a different answer.
         */
        return FALSE;
    }

    /* All 3 attempts exhausted with network errors */
    if (status_code) {
        *status_code = 0;
    }
    return FALSE;
}
