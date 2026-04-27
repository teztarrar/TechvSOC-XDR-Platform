/*
 * Event Forwarding Aggregator - Windows Agent v2
 * TechvSOC XDR Platform
 *
 * Native Windows agent: Windows Event Log subscriptions + system metrics
 * + file log forwarding.
 * Log shipping: raw TCP syslog RFC 5424 (newline-framed).
 * Registration + metrics: WinHTTP REST (JWT Bearer auth).
 *
 * Monitors Palantir WEF-recommended channels for intrusion detection.
 * Minimal system tray interface.
 */

#pragma comment(lib, "wevtapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "shell32.lib")

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <shellapi.h>
#include <winevt.h>
#include <strsafe.h>
#include <iphlpapi.h>
#include <ws2def.h>
#include <ws2ipdef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "resource.h"
#include "http_client.h"
#include "json_builder.h"
#include "metrics.h"
#include "log_reader.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define WM_TRAYICON         (WM_USER + 1)
#define IDM_SHOW_STATUS     1001
#define IDM_RESTART         1002
#define IDM_EXIT            1003

#define IDT_STATUS_TIMER    2001

#define MAX_PATH_LEN        260
#define MAX_HOST_LEN        256
#define MAX_CHANNELS        32
#define STATUS_INTERVAL     1000   /* ms */

#define MAX_BACKEND_URL     512
#define MAX_TOKEN_LEN       512
#define EVENT_QUEUE_SIZE    4096
#define EVENT_QUEUE_MASK    (EVENT_QUEUE_SIZE - 1)
#define MAX_EVENT_JSON      65536   /* max bytes for one event JSON object */
#define STATE_FILENAME      L"event_forwarder_state.ini"
#define DEFAULT_METRICS_INTERVAL    30
#define DEFAULT_LOG_INTERVAL        60
#define DEFAULT_EVENT_FLUSH_INTERVAL 10
#define DEFAULT_EVENT_FLUSH_BATCH   50

#define MAX_SYSLOG_HOST     256
#define MAX_SYSLOG_PORT     8
#define MAX_SYSLOG_LINE     (MAX_EVENT_JSON + 256)  /* RFC 5424 header overhead */
#define RECONNECT_INTERVAL  5000   /* ms between TCP reconnect attempts */
#define DEFAULT_SYSLOG_HOST "127.0.0.1"
#define DEFAULT_SYSLOG_PORT "5514"

#define APP_NAME            L"TechvSOC Event Forwarder"
#define APP_CLASS           L"TechvSOCEventForwarder"
#define INI_FILENAME        L"event_forwarder.ini"
#define BOOKMARK_FILENAME   L"event_forwarder.bm"

/* ------------------------------------------------------------------ */
/*  All monitored channels (General SOC + Palantir WEF comprehensive) */
/*  Covers: Security, System, Application, Sysmon, PowerShell,        */
/*  Defender, McAfee, Terminal Services, Remote Access, DNS,          */
/*  TaskScheduler, BITS, Firewall, WMI, Print, DNS Client,            */
/*  Kernel, BitLocker, Code Integrity, LSA, Audit, SMB, DHCP,        */
/*  NTLM, Kerberos, Windows Update, RemoteDesktop, WinRM              */
/* ------------------------------------------------------------------ */

typedef struct _CHANNEL_ENTRY {
    const WCHAR* name;        /* event channel path                       */
    const WCHAR* query;       /* XPath query (NULL = "*")                 */
    const WCHAR* provider;    /* provider name for identification         */
    const WCHAR* category;    /* human-readable category for status       */
} CHANNEL_ENTRY;

static const CHANNEL_ENTRY g_channel_entries[MAX_CHANNELS] = {
    /* -- Core Windows Administrative Channels -- */
    { L"Security",            NULL, NULL, L"Security" },
    { L"System",              NULL, NULL, L"System" },
    { L"Application",         NULL, NULL, L"Application" },

    /* -- Sysmon (process, network, file, registry, image load) -- */
    { L"Microsoft-Windows-Sysmon/Operational",
      NULL,
      L"Microsoft-Windows-Sysmon",
      L"Sysmon" },

    /* -- PowerShell (script block, module, console logging) -- */
    { L"Microsoft-Windows-PowerShell/Operational",
      NULL,
      L"Microsoft-Windows-PowerShell",
      L"PowerShell" },

    /* -- Windows Defender (malware detection, scans, remediation) -- */
    { L"Microsoft-Windows-Windows Defender/Operational",
      NULL,
      L"Microsoft-Windows-Windows Defender",
      L"Windows Defender" },

    /* -- Terminal Services / RDP -- */
    { L"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
      NULL,
      L"Microsoft-Windows-TerminalServices-LocalSessionManager",
      L"Terminal Services - Local Session" },
    { L"Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
      NULL,
      L"Microsoft-Windows-TerminalServices-RemoteConnectionManager",
      L"Terminal Services - Remote Connection" },
    { L"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
      NULL,
      L"Microsoft-Windows-RemoteDesktopServices-RdpCoreTS",
      L"RDP Core" },

    /* -- Task Scheduler -- */
    { L"Microsoft-Windows-TaskScheduler/Operational",
      NULL, NULL, L"Task Scheduler" },

    /* -- Windows Firewall -- */
    { L"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
      NULL, NULL, L"Windows Firewall" },

    /* -- BITS (Background Intelligent Transfer Service) -- */
    { L"Microsoft-Windows-Bits-Client/Operational",
      NULL, NULL, L"BITS Client" },

    /* -- WMI Activity -- */
    { L"Microsoft-Windows-WMI-Activity/Operational",
      NULL,
      L"Microsoft-Windows-WMI-Activity",
      L"WMI Activity" },

    /* -- DNS Client -- */
    { L"Microsoft-Windows-DNS-Client/Operational",
      NULL, NULL, L"DNS Client" },

    /* -- Print Service (document audit) -- */
    { L"Microsoft-Windows-PrintService/Operational",
      NULL,
      L"Microsoft-Windows-PrintService",
      L"Print Service" },

    /* -- Code Integrity (driver/module signing) -- */
    { L"Microsoft-Windows-CodeIntegrity/Operational",
      NULL, NULL, L"Code Integrity" },

    /* -- BitLocker Drive Encryption -- */
    { L"Microsoft-Windows-BitLocker/BitLocker Management",
      NULL, NULL, L"BitLocker" },

    /* -- LSA (Lsass.exe authentication) -- */
    { L"Microsoft-Windows-LsaSrv/Operational",
      NULL, NULL, L"LSA" },

    /* -- Security Audit (audit policy changes) -- */
    { L"Microsoft-Windows-Security-Auditing",
      NULL, NULL, L"Security Auditing" },

    /* -- SMB Client / Server -- */
    { L"Microsoft-Windows-SmbClient/Operational",
      NULL, NULL, L"SMB Client" },
    { L"Microsoft-Windows-SmbServer/Operational",
      NULL, NULL, L"SMB Server" },

    /* -- DHCP Client -- */
    { L"Microsoft-Windows-Dhcp-Client/Operational",
      NULL, NULL, L"DHCP Client" },

    /* -- NTLM (authentication audit) -- */
    { L"Microsoft-Windows-NTLM/Operational",
      NULL, NULL, L"NTLM" },

    /* -- Kerberos (ticket audit) -- */
    { L"Microsoft-Windows-Kerberos/Operational",
      NULL, NULL, L"Kerberos" },

    /* -- Windows Update -- */
    { L"Microsoft-Windows-WindowsUpdateClient/Operational",
      NULL, NULL, L"Windows Update" },

    /* -- WinRM (remote management) -- */
    { L"Microsoft-Windows-WinRM/Operational",
      NULL, NULL, L"WinRM" },

    /* -- Remote Access / VPN -- */
    { L"Microsoft-Windows-RemoteAccess/Operational",
      NULL, NULL, L"Remote Access" },

    /* -- Kernel (general system events) -- */
    { L"Microsoft-Windows-Kernel-General/Operational",
      NULL, NULL, L"Kernel General" },

    /* -- File Replication Service (NTFRS) -- */
    { L"Microsoft-Windows-FileReplicationService/Operational",
      NULL, NULL, L"File Replication" },

    /* -- McAfee (via Application log + McLogEvent provider) -- */
    { L"Application",
      L"Event/System[Provider[@Name='McLogEvent']]",
      L"McLogEvent",
      L"McAfee" },

    /* -- Microsoft Antimalware (Security Essentials) -- */
    { L"System",
      L"Event/System[Provider[@Name='Microsoft Antimalware']]",
      L"Microsoft Antimalware",
      L"Microsoft Antimalware" },

    /* -- EventLog source within System channel -- */
    { L"System",
      L"Event/System[Provider[@Name='Eventlog']]",
      L"Eventlog",
      L"EventLog Source" },
};

#define CHANNEL_COUNT (sizeof(g_channel_entries) / sizeof(g_channel_entries[0]))

/* ------------------------------------------------------------------ */
/*  Key Security Event IDs                                            */
/* ------------------------------------------------------------------ */

static const DWORD g_key_event_ids[] = {
    4624, 4625, 4634, 4648, 4672, 4688, 4697, 4702,
    4720, 4732, 4740, 4756, 4767, 4768, 4769, 4771,
    4776, 5136, 5140, 5142, 5145, 7034, 7036, 7045
};
#define KEY_EVENT_COUNT (sizeof(g_key_event_ids) / sizeof(g_key_event_ids[0]))

/* ------------------------------------------------------------------ */
/*  Data types                                                        */
/* ------------------------------------------------------------------ */

/* Per-subscription bookmark state */
typedef struct _CHANNEL_BOOKMARK {
    const WCHAR*        channel;
    EVT_HANDLE          bookmark;
} CHANNEL_BOOKMARK;

/* Global application state */
typedef struct _APP_STATE {
    /* Configuration */
    WCHAR               ini_path[MAX_PATH];
    WCHAR               bookmark_path[MAX_PATH];

    /* ------------------------------------------------------------------ */
    /*  Backend configuration                                             */
    /* ------------------------------------------------------------------ */
    char    backend_url[512];       /* e.g. "http://localhost:8000/api/v1" */
    char    backend_token[512];     /* JWT bearer token                     */
    BOOL    tls_verify;
    int     metrics_interval;       /* seconds, default 30                  */
    int     log_interval;           /* seconds, default 60                  */
    int     event_flush_interval;   /* seconds, default 10                  */
    int     event_flush_batch;      /* events per HTTP POST, default 50     */
    char    agent_version[32];

    /* ------------------------------------------------------------------ */
    /*  Syslog TCP (log shipping)                                         */
    /* ------------------------------------------------------------------ */
    char    syslog_host[MAX_SYSLOG_HOST];
    char    syslog_port[MAX_SYSLOG_PORT];
    SOCKET  syslog_sock;
    BOOL    syslog_connected;
    WSADATA wsa_data;
    CRITICAL_SECTION syslog_lock;   /* protects syslog_sock for multi-thread send */

    /* Endpoint registration */
    int     endpoint_id;            /* 0 = not yet registered               */
    WCHAR   state_path[MAX_PATH];   /* INI file for persistent state        */

    /* Log file reader config */
    LogReaderConfig log_reader_cfg;

    /* Event queue — ring buffer of heap-alloc'd JSON object strings       */
    CRITICAL_SECTION queue_lock;
    char*    event_queue[EVENT_QUEUE_SIZE];
    size_t   event_queue_lens[EVENT_QUEUE_SIZE];
    int      event_queue_head;
    int      event_queue_tail;
    HANDLE   queue_event;

    /* Threading */
    HANDLE   event_worker_thread;
    HANDLE   metrics_thread;
    HANDLE   log_reader_thread;
    volatile LONG shutdown;

    /* Statistics */
    volatile LONG64 events_collected;
    volatile LONG64 events_sent;
    volatile LONG64 metrics_sent;
    DWORD    start_tick;

    /* Subscriptions */
    EVT_HANDLE          subscriptions[MAX_CHANNELS];
    CHANNEL_BOOKMARK    bookmarks[MAX_CHANNELS];
    int                 sub_count;
    BOOL                channel_active[MAX_CHANNELS];

    /* Windowing */
    HWND                msg_window;
    NOTIFYICONDATAW     nid;
    HMENU               tray_menu;
    HWND                status_dialog;
} APP_STATE;

static APP_STATE g_state;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                              */
/* ------------------------------------------------------------------ */

static BOOL     LoadConfiguration(void);
static BOOL     SaveBookmarks(void);
static BOOL     LoadBookmarks(void);
static BOOL     StartSubscriptions(void);
static void     StopSubscriptions(void);
static BOOL     IsKeyEventId(DWORD event_id);
static char*    WideToUtf8Alloc(const WCHAR* wide);
static BOOL     GetLocalHostname(char* buf, size_t bufsz);
static BOOL     GetPrimaryIpAddress(char* buf, size_t bufsz);
static void     GetWindowsVersionString(char* buf, size_t bufsz);
static void     SaveEndpointId(int id);
static int      RegisterEndpoint(HTTP_CLIENT* client);

/* Event formatting */
static BOOL     ExtractXmlField(const char* xml, const char* open_tag,
                                 const char* close_tag, char* out, size_t outsz);
static BOOL     ExtractXmlAttr(const char* xml, const char* tag_name,
                                const char* attr_name, char* out, size_t outsz);
static const char* WindowsLevelToSeverity(int level);
static void     FormatWindowsEventJson(char* buf, size_t bufsz,
                                        const char* xml_utf8,
                                        int endpoint_id,
                                        const char* channel_category);

/* Winsock / TCP syslog */
static BOOL     InitializeWinsock(void);
static void     CleanupWinsock(void);
static BOOL     ConnectSyslog(void);
static void     DisconnectSyslog(void);
static BOOL     SyslogSendAll(const char* data, size_t len);
static void     FormatLogSyslogLine(char* buf, size_t bufsz,
                                     const char* hostname,
                                     const char* json_payload);
static void     FormatLREntryJson(char* buf, size_t bufsz,
                                   const LRLogEntry* entry);
static BOOL     EnqueueLogJson(const char* json, size_t len);

/* Worker threads */
static DWORD WINAPI EventWorkerThread(LPVOID param);
static DWORD WINAPI MetricsThread(LPVOID param);
static DWORD WINAPI LogReaderThread(LPVOID param);

/* Window / tray */
static BOOL     RegisterWindowClass(HINSTANCE inst);
static BOOL     CreateMessageWindow(HINSTANCE inst);
static BOOL     AddTrayIcon(void);
static void     RemoveTrayIcon(void);
static void     ShowContextMenu(HWND hwnd);
static void     ShowNotification(DWORD icon_type, const WCHAR* title, const WCHAR* text);
static INT_PTR CALLBACK StatusDlgProc(HWND hdlg, UINT msg,
                                       WPARAM wp, LPARAM lp);

/* EvtSubscribe callback */
static DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                   PVOID context, EVT_HANDLE event);

/* ------------------------------------------------------------------ */
/*  Utility helpers                                                   */
/* ------------------------------------------------------------------ */

static char* WideToUtf8Alloc(const WCHAR* wide)
{
    if (!wide) return NULL;
    int len = WideCharToMultiByte(CP_UTF8, 0, wide, -1, NULL, 0, NULL, NULL);
    if (len <= 0) return NULL;
    char* utf8 = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (size_t)len);
    if (!utf8) return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, utf8, len, NULL, NULL);
    return utf8;
}

static BOOL GetLocalHostname(char* buf, size_t bufsz)
{
    WCHAR whost[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = MAX_COMPUTERNAME_LENGTH + 1;
    if (!GetComputerNameW(whost, &size)) {
        StringCchCopyA(buf, bufsz, "unknown");
        return FALSE;
    }
    WideCharToMultiByte(CP_UTF8, 0, whost, -1, buf, (int)bufsz, NULL, NULL);
    return TRUE;
}

static BOOL IsKeyEventId(DWORD event_id)
{
    for (int i = 0; i < (int)KEY_EVENT_COUNT; i++) {
        if (g_key_event_ids[i] == event_id)
            return TRUE;
    }
    return FALSE;
}

/* Read a string value from the INI file */
static void GetIniString(const WCHAR* section, const WCHAR* key,
                          const WCHAR* defval, WCHAR* buf, DWORD bufsz)
{
    GetPrivateProfileStringW(section, key, defval, buf, bufsz, g_state.ini_path);
}

/* ------------------------------------------------------------------ */
/*  Network helpers                                                   */
/* ------------------------------------------------------------------ */

static BOOL GetPrimaryIpAddress(char* buf, size_t bufsz)
{
    /* Use GetAdaptersAddresses to find first non-loopback IPv4 address */
    ULONG size = 0;
    GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST |
                         GAA_FLAG_SKIP_DNS_SERVER, NULL, NULL, &size);
    if (size == 0) { StringCchCopyA(buf, bufsz, "0.0.0.0"); return FALSE; }

    PIP_ADAPTER_ADDRESSES addrs = (PIP_ADAPTER_ADDRESSES)HeapAlloc(
        GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    if (!addrs) { StringCchCopyA(buf, bufsz, "0.0.0.0"); return FALSE; }

    BOOL found = FALSE;
    if (GetAdaptersAddresses(AF_INET, GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_ANYCAST |
                              GAA_FLAG_SKIP_DNS_SERVER, NULL, addrs, &size) == NO_ERROR) {
        PIP_ADAPTER_ADDRESSES a;
        for (a = addrs; a && !found; a = a->Next) {
            if (a->OperStatus != IfOperStatusUp) continue;
            if (a->IfType == IF_TYPE_SOFTWARE_LOOPBACK) continue;
            PIP_ADAPTER_UNICAST_ADDRESS ua;
            for (ua = a->FirstUnicastAddress; ua && !found; ua = ua->Next) {
                struct sockaddr_in* sa = (struct sockaddr_in*)ua->Address.lpSockaddr;
                if (sa->sin_family == AF_INET) {
                    DWORD ip = ntohl(sa->sin_addr.S_un.S_addr);
                    StringCchPrintfA(buf, bufsz, "%d.%d.%d.%d",
                        (ip>>24)&0xFF,(ip>>16)&0xFF,(ip>>8)&0xFF,ip&0xFF);
                    found = TRUE;
                }
            }
        }
    }
    HeapFree(GetProcessHeap(), 0, addrs);
    if (!found) StringCchCopyA(buf, bufsz, "0.0.0.0");
    return found;
}

typedef LONG(WINAPI* RtlGetVersionFn)(OSVERSIONINFOW*);
static void GetWindowsVersionString(char* buf, size_t bufsz)
{
    OSVERSIONINFOW vi;
    vi.dwOSVersionInfoSize = sizeof(vi);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    RtlGetVersionFn fn = ntdll
        ? (RtlGetVersionFn)GetProcAddress(ntdll, "RtlGetVersion")
        : NULL;
    if (fn && fn(&vi) == 0) {
        StringCchPrintfA(buf, bufsz, "Windows %lu.%lu Build %lu",
            vi.dwMajorVersion, vi.dwMinorVersion, vi.dwBuildNumber);
    } else {
        StringCchCopyA(buf, bufsz, "Windows");
    }
}

/* ------------------------------------------------------------------ */
/*  Configuration                                                     */
/* ------------------------------------------------------------------ */

static BOOL LoadConfiguration(void)
{
    /* Build path to INI in same directory as EXE */
    WCHAR exe_path[MAX_PATH];
    GetModuleFileNameW(NULL, exe_path, MAX_PATH);

    /* Find last backslash — extract directory */
    WCHAR* slash = wcsrchr(exe_path, L'\\');
    if (!slash) {
        return FALSE;
    }
    *(slash + 1) = L'\0';
    /* exe_path is now the directory (with trailing backslash) */
    WCHAR exe_dir[MAX_PATH];
    StringCchCopyW(exe_dir, MAX_PATH, exe_path);

    StringCchCopyW(g_state.ini_path, MAX_PATH, exe_dir);
    StringCchCatW(g_state.ini_path, MAX_PATH, INI_FILENAME);

    StringCchCopyW(g_state.bookmark_path, MAX_PATH, exe_dir);
    StringCchCatW(g_state.bookmark_path, MAX_PATH, BOOKMARK_FILENAME);

    WCHAR wval[MAX_BACKEND_URL];

    /* [backend] */
    GetIniString(L"backend", L"url", L"http://localhost:8000/api/v1", wval, MAX_BACKEND_URL);
    WideCharToMultiByte(CP_UTF8, 0, wval, -1, g_state.backend_url, MAX_BACKEND_URL, NULL, NULL);

    GetIniString(L"backend", L"token", L"", wval, MAX_TOKEN_LEN);
    WideCharToMultiByte(CP_UTF8, 0, wval, -1, g_state.backend_token, MAX_TOKEN_LEN, NULL, NULL);

    GetIniString(L"backend", L"tls_verify", L"1", wval, 8);
    g_state.tls_verify = (_wtoi(wval) != 0);

    /* [syslog] — TCP log shipping */
    WCHAR wsyslog_host[MAX_SYSLOG_HOST];
    WCHAR wsyslog_port[MAX_SYSLOG_PORT];
    GetIniString(L"syslog", L"host", L"127.0.0.1", wsyslog_host, MAX_SYSLOG_HOST);
    GetIniString(L"syslog", L"port", L"5514",       wsyslog_port, MAX_SYSLOG_PORT);
    WideCharToMultiByte(CP_UTF8, 0, wsyslog_host, -1,
                        g_state.syslog_host, MAX_SYSLOG_HOST, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, wsyslog_port, -1,
                        g_state.syslog_port, MAX_SYSLOG_PORT, NULL, NULL);

    /* [agent] */
    g_state.metrics_interval    = GetPrivateProfileIntW(L"agent", L"metrics_interval",    DEFAULT_METRICS_INTERVAL,     g_state.ini_path);
    g_state.log_interval        = GetPrivateProfileIntW(L"agent", L"log_interval",         DEFAULT_LOG_INTERVAL,          g_state.ini_path);
    g_state.event_flush_interval= GetPrivateProfileIntW(L"agent", L"event_flush_interval", DEFAULT_EVENT_FLUSH_INTERVAL,  g_state.ini_path);
    g_state.event_flush_batch   = GetPrivateProfileIntW(L"agent", L"event_flush_batch",    DEFAULT_EVENT_FLUSH_BATCH,     g_state.ini_path);
    g_state.endpoint_id         = GetPrivateProfileIntW(L"agent", L"endpoint_id",          0,                             g_state.ini_path);

    GetIniString(L"agent", L"version", L"2.0.0", wval, 32);
    WideCharToMultiByte(CP_UTF8, 0, wval, -1, g_state.agent_version, 32, NULL, NULL);

    /* Build state path */
    StringCchCopyW(g_state.state_path, MAX_PATH, exe_dir);
    StringCchCatW(g_state.state_path, MAX_PATH, STATE_FILENAME);

    /* [log_files] */
    int log_count = GetPrivateProfileIntW(L"log_files", L"count", 0, g_state.ini_path);
    g_state.log_reader_cfg.count = 0;
    int i;
    for (i = 1; i <= log_count && i <= LR_MAX_FILES; i++) {
        WCHAR key[32], val[MAX_PATH];
        StringCchPrintfW(key, 32, L"file_%02d", i);
        GetPrivateProfileStringW(L"log_files", key, L"", val, MAX_PATH, g_state.ini_path);
        if (val[0]) {
            StringCchCopyW(g_state.log_reader_cfg.paths[g_state.log_reader_cfg.count++],
                           LR_MAX_PATH, val);
        }
    }
    /* offset file: same dir as state file, named log_offsets.ini */
    StringCchCopyW(g_state.log_reader_cfg.offset_file, LR_MAX_PATH, exe_dir);
    StringCchCatW(g_state.log_reader_cfg.offset_file, LR_MAX_PATH, L"log_offsets.ini");

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Winsock / TCP syslog                                              */
/* ------------------------------------------------------------------ */

static BOOL InitializeWinsock(void)
{
    return (WSAStartup(MAKEWORD(2, 2), &g_state.wsa_data) == 0);
}

static void CleanupWinsock(void)
{
    WSACleanup();
}

static BOOL ConnectSyslog(void)
{
    if (g_state.syslog_connected) return TRUE;

    struct addrinfo hints, *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(g_state.syslog_host, g_state.syslog_port, &hints, &result) != 0)
        return FALSE;

    g_state.syslog_sock = socket(result->ai_family, result->ai_socktype,
                                  result->ai_protocol);
    if (g_state.syslog_sock == INVALID_SOCKET) {
        freeaddrinfo(result);
        return FALSE;
    }

    /* 10-second send timeout */
    DWORD timeout = 10000;
    setsockopt(g_state.syslog_sock, SOL_SOCKET, SO_SNDTIMEO,
               (const char*)&timeout, sizeof(timeout));

    /* TCP_NODELAY for low-latency streaming */
    int nodelay = 1;
    setsockopt(g_state.syslog_sock, IPPROTO_TCP, TCP_NODELAY,
               (const char*)&nodelay, sizeof(nodelay));

    if (connect(g_state.syslog_sock, result->ai_addr,
                (int)result->ai_addrlen) == SOCKET_ERROR) {
        closesocket(g_state.syslog_sock);
        g_state.syslog_sock = INVALID_SOCKET;
        freeaddrinfo(result);
        return FALSE;
    }

    freeaddrinfo(result);
    g_state.syslog_connected = TRUE;
    return TRUE;
}

static void DisconnectSyslog(void)
{
    if (g_state.syslog_sock != INVALID_SOCKET) {
        shutdown(g_state.syslog_sock, SD_BOTH);
        closesocket(g_state.syslog_sock);
        g_state.syslog_sock = INVALID_SOCKET;
    }
    g_state.syslog_connected = FALSE;
}

static BOOL SyslogSendAll(const char* data, size_t len)
{
    size_t sent = 0;
    while (sent < len) {
        int n = send(g_state.syslog_sock, data + sent, (int)(len - sent), 0);
        if (n == SOCKET_ERROR) return FALSE;
        sent += (size_t)n;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Log formatting helpers                                            */
/* ------------------------------------------------------------------ */

/*
 * FormatLogSyslogLine — wrap a JSON LogEventPayload in RFC 5424.
 * Output: "<134>1 TIMESTAMP HOSTNAME TECHVSOC-AGENT PROCID - - {json}\n"
 * Always NUL-terminates. Truncates gracefully.
 */
static void FormatLogSyslogLine(char*       buf,
                                 size_t      bufsz,
                                 const char* hostname,
                                 const char* json_payload)
{
    SYSTEMTIME st;
    GetSystemTime(&st);
    char ts[32];
    StringCchPrintfA(ts, sizeof(ts), "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    /* PRI = local0(16)*8 + info(6) = 134 */
    StringCchPrintfA(buf, bufsz,
        "<134>1 %s %s TECHVSOC-AGENT %lu - - %s\n",
        ts,
        (hostname && hostname[0]) ? hostname : "-",
        (unsigned long)GetCurrentProcessId(),
        json_payload ? json_payload : "{}");
}

/*
 * FormatLREntryJson — convert an LRLogEntry to a LogEventPayload JSON object.
 * Used by LogReaderThread to enqueue file-log entries into the shared ring buffer.
 */
static void FormatLREntryJson(char* buf, size_t bufsz, const LRLogEntry* e)
{
    JsonBuilder jb;
    JsonInit(&jb, buf, bufsz);
    JsonObjectBegin(&jb);
    JsonStr    (&jb, "source",          e->source);
    JsonStr    (&jb, "event_type",      e->event_type);
    JsonStr    (&jb, "message",         e->message);
    JsonStr    (&jb, "raw_log",         e->raw_log);
    JsonStr    (&jb, "severity",        e->severity);
    JsonStr    (&jb, "event_timestamp", e->event_timestamp);
    if (e->endpoint_id > 0)
        JsonInt(&jb, "endpoint_id",     e->endpoint_id);
    JsonNestedObjectBegin(&jb, "metadata_json");
    JsonStr    (&jb, "file_path",       e->file_path);
    JsonStr    (&jb, "source_type",     "file_log");
    JsonNestedObjectEnd(&jb);
    JsonObjectEnd(&jb);
    JsonFinish(&jb);
}

/*
 * EnqueueLogJson — thread-safe push to event ring buffer.
 * Takes ownership of a heap-allocated JSON string.
 * Drops oldest entry if queue full.
 */
static BOOL EnqueueLogJson(const char* json, size_t len)
{
    char* copy = (char*)HeapAlloc(GetProcessHeap(), 0, len + 1);
    if (!copy) return FALSE;
    memcpy(copy, json, len);
    copy[len] = '\0';

    EnterCriticalSection(&g_state.queue_lock);
    int next_tail = (g_state.event_queue_tail + 1) & EVENT_QUEUE_MASK;
    if (next_tail == g_state.event_queue_head) {
        /* Queue full — drop oldest */
        HeapFree(GetProcessHeap(), 0, g_state.event_queue[g_state.event_queue_head]);
        g_state.event_queue[g_state.event_queue_head] = NULL;
        g_state.event_queue_head = (g_state.event_queue_head + 1) & EVENT_QUEUE_MASK;
    }
    g_state.event_queue[g_state.event_queue_tail]      = copy;
    g_state.event_queue_lens[g_state.event_queue_tail] = len;
    g_state.event_queue_tail = next_tail;
    LeaveCriticalSection(&g_state.queue_lock);

    SetEvent(g_state.queue_event);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Endpoint registration persistence                                 */
/* ------------------------------------------------------------------ */

static void SaveEndpointId(int id)
{
    WCHAR val[32];
    StringCchPrintfW(val, 32, L"%d", id);
    WritePrivateProfileStringW(L"agent", L"endpoint_id", val, g_state.ini_path);
}

/* ------------------------------------------------------------------ */
/*  Bookmark persistence                                              */
/* ------------------------------------------------------------------ */

static BOOL SaveBookmarks(void)
{
    int i;
    for (i = 0; i < g_state.sub_count; i++) {
        if (!g_state.bookmarks[i].bookmark)
            continue;

        DWORD prop_count = 0;
        DWORD buffer_size = 0;
        if (!EvtRender(NULL, g_state.bookmarks[i].bookmark,
                        EvtRenderBookmark, 0, NULL,
                        &buffer_size, &prop_count)) {
            if (GetLastError() != ERROR_INSUFFICIENT_BUFFER)
                continue;
        }

        WCHAR* bm_xml = (WCHAR*)HeapAlloc(GetProcessHeap(),
                                            HEAP_ZERO_MEMORY, buffer_size);
        if (!bm_xml) continue;

        if (!EvtRender(NULL, g_state.bookmarks[i].bookmark,
                        EvtRenderBookmark, buffer_size, bm_xml,
                        &buffer_size, &prop_count)) {
            HeapFree(GetProcessHeap(), 0, bm_xml);
            continue;
        }

        WritePrivateProfileStringW(g_state.bookmarks[i].channel,
                                    L"bookmark",
                                    bm_xml,
                                    g_state.bookmark_path);
        HeapFree(GetProcessHeap(), 0, bm_xml);
    }
    return TRUE;
}

static BOOL LoadBookmarks(void)
{
    int i;
    for (i = 0; i < (int)CHANNEL_COUNT; i++) {
        WCHAR bm_xml[MAX_PATH * 4] = { 0 };
        GetPrivateProfileStringW(g_channel_entries[i].name, L"bookmark", L"",
                                  bm_xml, MAX_PATH * 4,
                                  g_state.bookmark_path);

        if (wcslen(bm_xml) > 0) {
            g_state.bookmarks[i].bookmark = EvtCreateBookmark(bm_xml);
            if (!g_state.bookmarks[i].bookmark) {
                g_state.bookmarks[i].bookmark = NULL;
            }
        }
        g_state.bookmarks[i].channel = g_channel_entries[i].name;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Endpoint registration                                             */
/* ------------------------------------------------------------------ */

static int RegisterEndpoint(HTTP_CLIENT* client)
{
    char hostname[256] = {0};
    GetLocalHostname(hostname, sizeof(hostname));

    char ip[64] = {0};
    GetPrimaryIpAddress(ip, sizeof(ip));

    char os_ver[128] = {0};
    GetWindowsVersionString(os_ver, sizeof(os_ver));

    /* Build JSON matching Python EndpointRegistrationPayload model */
    char json_buf[2048];
    JsonBuilder b;
    JsonInit(&b, json_buf, sizeof(json_buf));
    JsonObjectBegin(&b);
    JsonStr(&b, "hostname",         hostname);
    JsonStr(&b, "ip_address",       ip);
    JsonStr(&b, "operating_system", os_ver);
    JsonStr(&b, "agent_version",    g_state.agent_version);
    JsonStr(&b, "status",           "online");
    JsonStr(&b, "last_seen_ip",     ip);
    JsonStr(&b, "notes",            "Registered by TechvSOC XDR Native Agent");
    JsonObjectEnd(&b);
    JsonFinish(&b);

    char resp[1024] = {0};
    int status = 0;
    if (!HttpPost(client, "/monitoring/endpoints/register",
                  json_buf, resp, sizeof(resp), &status)) {
        return 0;
    }

    /* Parse "id" from response JSON: find "\"id\":" then integer */
    const char* id_pos = strstr(resp, "\"id\":");
    if (!id_pos) id_pos = strstr(resp, "\"id\" :");
    if (id_pos) {
        id_pos += 5;
        while (*id_pos == ' ') id_pos++;
        int id = atoi(id_pos);
        if (id > 0) return id;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  XML parsing helpers for Windows Event XML                         */
/* ------------------------------------------------------------------ */

static BOOL ExtractXmlField(const char* xml, const char* open_tag,
                              const char* close_tag, char* out, size_t outsz)
{
    const char* p = strstr(xml, open_tag);
    if (!p) return FALSE;
    p += strlen(open_tag);
    const char* q = strstr(p, close_tag);
    if (!q) return FALSE;
    size_t len = (size_t)(q - p);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, p, len);
    out[len] = '\0';
    return TRUE;
}

/* Extract attribute value from: <Tag AttrName='value' ... */
static BOOL ExtractXmlAttr(const char* xml, const char* tag_name,
                             const char* attr_name, char* out, size_t outsz)
{
    char search[256];
    StringCchPrintfA(search, sizeof(search), "<%s ", tag_name);
    const char* tag = strstr(xml, search);
    if (!tag) return FALSE;

    char attr_search[256];
    StringCchPrintfA(attr_search, sizeof(attr_search), "%s='", attr_name);
    const char* attr = strstr(tag, attr_search);
    if (!attr) return FALSE;
    attr += strlen(attr_search);

    const char* end = strchr(attr, '\'');
    if (!end) return FALSE;
    size_t len = (size_t)(end - attr);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, attr, len);
    out[len] = '\0';
    return TRUE;
}

static const char* WindowsLevelToSeverity(int level)
{
    switch (level) {
    case 1:  return "critical";
    case 2:  return "error";
    case 3:  return "warning";
    case 4:  return "info";
    case 5:  return "debug";
    default: return "info";
    }
}

static void FormatWindowsEventJson(char*       buf,
                                    size_t      bufsz,
                                    const char* xml_utf8,
                                    int         endpoint_id,
                                    const char* channel_category)
{
    char event_id[32]    = "0";
    char level_str[8]    = "4";
    char channel[256]    = "";
    char computer[256]   = "";
    char time_created[64]= "";

    ExtractXmlField(xml_utf8, "<EventID>",   "</EventID>",   event_id,    sizeof(event_id));
    ExtractXmlField(xml_utf8, "<Level>",     "</Level>",     level_str,   sizeof(level_str));
    ExtractXmlField(xml_utf8, "<Channel>",   "</Channel>",   channel,     sizeof(channel));
    ExtractXmlField(xml_utf8, "<Computer>",  "</Computer>",  computer,    sizeof(computer));
    ExtractXmlAttr (xml_utf8, "TimeCreated", "SystemTime",   time_created,sizeof(time_created));

    int level     = atoi(level_str);
    int evid      = atoi(event_id);
    const char* sev = WindowsLevelToSeverity(level);

    /* Human-readable summary message */
    char message[512];
    StringCchPrintfA(message, sizeof(message),
        "Windows Event ID %s on %s [%s]",
        event_id,
        computer[0] ? computer : "unknown",
        channel[0]  ? channel  : (channel_category ? channel_category : "Unknown"));

    /* Truncate XML to 10000 chars for raw_log */
    char raw_log[10001];
    StringCchCopyA(raw_log, sizeof(raw_log), xml_utf8);  /* truncates at 10000 */

    /* Build JSON object */
    JsonBuilder jb;
    JsonInit(&jb, buf, bufsz);
    JsonObjectBegin(&jb);
    JsonStr    (&jb, "source",          channel[0] ? channel : "windows_event");
    JsonStr    (&jb, "event_type",      "windows_event");
    JsonStr    (&jb, "message",         message);
    JsonStr    (&jb, "raw_log",         raw_log);
    JsonStr    (&jb, "severity",        sev);
    JsonStr    (&jb, "event_timestamp", time_created[0] ? time_created : "");
    if (endpoint_id > 0)
        JsonInt(&jb, "endpoint_id",     endpoint_id);
    JsonNestedObjectBegin(&jb, "metadata_json");
    JsonInt    (&jb, "event_id",        evid);
    JsonStr    (&jb, "channel",         channel);
    JsonInt    (&jb, "level",           level);
    JsonStr    (&jb, "computer",        computer);
    JsonNestedObjectEnd(&jb);
    JsonObjectEnd(&jb);
    JsonFinish(&jb);
}

/* ------------------------------------------------------------------ */
/*  EvtSubscribe callback                                             */
/* ------------------------------------------------------------------ */

static DWORD WINAPI EventCallback(EVT_SUBSCRIBE_NOTIFY_ACTION action,
                                   PVOID context, EVT_HANDLE event)
{
    if (action != EvtSubscribeActionDeliver) {
        return ERROR_SUCCESS;
    }
    if (!event) {
        return ERROR_SUCCESS;
    }

    /* Render the event as XML */
    DWORD buffer_size = 0;
    DWORD buffer_used = 0;
    DWORD prop_count = 0;

    /* First call to determine required buffer size */
    EvtRender(NULL, event, EvtRenderEventXml, 0, NULL,
              &buffer_size, &prop_count);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER || buffer_size == 0) {
        return ERROR_SUCCESS;
    }

    WCHAR* xml_wide = (WCHAR*)HeapAlloc(GetProcessHeap(),
                                         HEAP_ZERO_MEMORY, buffer_size);
    if (!xml_wide) return ERROR_SUCCESS;

    if (!EvtRender(NULL, event, EvtRenderEventXml, buffer_size,
                    xml_wide, &buffer_used, &prop_count)) {
        HeapFree(GetProcessHeap(), 0, xml_wide);
        return ERROR_SUCCESS;
    }

    /* Convert XML to UTF-8 */
    char* xml_utf8 = WideToUtf8Alloc(xml_wide);
    HeapFree(GetProcessHeap(), 0, xml_wide);
    if (!xml_utf8) return ERROR_SUCCESS;

    /* Update bookmark for this subscription channel */
    EVT_HANDLE bm = EvtCreateBookmark(NULL);
    if (bm) {
        EvtUpdateBookmark(bm, event);
        int idx = (int)(LONG_PTR)context;
        if (idx >= 0 && idx < (int)CHANNEL_COUNT) {
            if (g_state.bookmarks[idx].bookmark) {
                EvtClose(g_state.bookmarks[idx].bookmark);
            }
            g_state.bookmarks[idx].bookmark = bm;
        } else {
            EvtClose(bm);
        }
    }

    /* Format as JSON log entry */
    char* json_buf = (char*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, MAX_EVENT_JSON);
    if (!json_buf) { HeapFree(GetProcessHeap(), 0, xml_utf8); return ERROR_SUCCESS; }

    /* Find channel_category for this subscription index */
    const char* cat = NULL;
    int idx = (int)(LONG_PTR)context;
    if (idx >= 0 && idx < (int)CHANNEL_COUNT && g_channel_entries[idx].category)
        cat = WideToUtf8Alloc(g_channel_entries[idx].category);

    FormatWindowsEventJson(json_buf, MAX_EVENT_JSON, xml_utf8, g_state.endpoint_id, cat);
    if (cat) HeapFree(GetProcessHeap(), 0, (void*)cat);
    HeapFree(GetProcessHeap(), 0, xml_utf8);

    size_t json_len = strlen(json_buf);
    EnqueueLogJson(json_buf, json_len);
    HeapFree(GetProcessHeap(), 0, json_buf);

    InterlockedIncrement64(&g_state.events_collected);

    return ERROR_SUCCESS;
}

/* ------------------------------------------------------------------ */
/*  Subscription management                                           */
/* ------------------------------------------------------------------ */

static BOOL StartSubscriptions(void)
{
    g_state.sub_count = 0;
    memset(g_state.channel_active, 0, sizeof(g_state.channel_active));

    LoadBookmarks();

    int i;
    for (i = 0; i < (int)CHANNEL_COUNT; i++) {
        EVT_HANDLE bookmark = g_state.bookmarks[i].bookmark;
        DWORD flags = EvtSubscribeToFutureEvents;

        if (bookmark) {
            flags = EvtSubscribeStartAfterBookmark;
        }

        const WCHAR* query = g_channel_entries[i].query;
        if (!query) {
            query = L"*";
        }

        EVT_HANDLE sub = EvtSubscribe(
            NULL,                          /* no signal event      */
            NULL,                          /* no callback event    */
            g_channel_entries[i].name,     /* channel path         */
            query,                         /* XPath query          */
            bookmark,                      /* bookmark             */
            (PVOID)(LONG_PTR)i,            /* context: channel idx */
            EventCallback,                 /* callback function    */
            flags);

        if (!sub) {
            /* If bookmark-based subscribe failed, try without bookmark */
            if (bookmark) {
                sub = EvtSubscribe(NULL, NULL, g_channel_entries[i].name,
                                    query, NULL, (PVOID)(LONG_PTR)i,
                                    EventCallback,
                                    EvtSubscribeToFutureEvents);
            }

            if (!sub) {
                /* Channel may not exist on this system (e.g. Sysmon not
                   installed, McAfee not present); skip silently */
                continue;
            }
        }

        g_state.subscriptions[g_state.sub_count] = sub;
        g_state.channel_active[i] = TRUE;
        g_state.sub_count++;
    }

    return (g_state.sub_count > 0);
}

static void StopSubscriptions(void)
{
    int i;
    /* Save bookmarks before closing subscriptions */
    SaveBookmarks();

    for (i = 0; i < g_state.sub_count; i++) {
        if (g_state.subscriptions[i]) {
            EvtClose(g_state.subscriptions[i]);
            g_state.subscriptions[i] = NULL;
        }
    }
    g_state.sub_count = 0;

    /* Close bookmarks */
    for (i = 0; i < (int)CHANNEL_COUNT; i++) {
        if (g_state.bookmarks[i].bookmark) {
            EvtClose(g_state.bookmarks[i].bookmark);
            g_state.bookmarks[i].bookmark = NULL;
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Worker threads                                                    */
/* ------------------------------------------------------------------ */

static DWORD WINAPI EventWorkerThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    char hostname[256] = {0};
    GetLocalHostname(hostname, sizeof(hostname));

    /* Syslog line buffer: RFC 5424 header + JSON payload */
    char* syslog_line = (char*)HeapAlloc(GetProcessHeap(), 0, MAX_SYSLOG_LINE);
    if (!syslog_line) return 1;

    DWORD last_flush = GetTickCount();

    while (!g_state.shutdown) {

        /* Reconnect if needed */
        if (!g_state.syslog_connected) {
            EnterCriticalSection(&g_state.syslog_lock);
            if (!g_state.syslog_connected) {
                if (!ConnectSyslog()) {
                    LeaveCriticalSection(&g_state.syslog_lock);
                    Sleep(RECONNECT_INTERVAL);
                    continue;
                }
                ShowNotification(NIIF_INFO, APP_NAME,
                    L"Syslog TCP connected — log shipping active");
            }
            LeaveCriticalSection(&g_state.syslog_lock);
        }

        /* Wait for events or flush timer */
        WaitForSingleObject(g_state.queue_event,
            (DWORD)(g_state.event_flush_interval * 1000));
        if (g_state.shutdown) break;

        /* Check flush conditions */
        DWORD queue_count = 0;
        EnterCriticalSection(&g_state.queue_lock);
        queue_count = (DWORD)((g_state.event_queue_tail - g_state.event_queue_head
                               + EVENT_QUEUE_SIZE) & EVENT_QUEUE_MASK);
        LeaveCriticalSection(&g_state.queue_lock);

        DWORD now = GetTickCount();
        BOOL time_to_flush =
            (queue_count >= (DWORD)g_state.event_flush_batch) ||
            (queue_count > 0 && (now - last_flush >=
             (DWORD)(g_state.event_flush_interval * 1000)));

        if (!time_to_flush) continue;

        /* Drain queue — send each entry as a syslog line */
        BOOL send_ok = TRUE;
        while (send_ok) {
            char* json_obj = NULL;
            size_t json_len = 0;

            EnterCriticalSection(&g_state.queue_lock);
            if (g_state.event_queue_head == g_state.event_queue_tail) {
                /* Queue empty */
                ResetEvent(g_state.queue_event);
                LeaveCriticalSection(&g_state.queue_lock);
                break;
            }
            json_obj = g_state.event_queue[g_state.event_queue_head];
            json_len = g_state.event_queue_lens[g_state.event_queue_head];
            g_state.event_queue[g_state.event_queue_head] = NULL;
            g_state.event_queue_head =
                (g_state.event_queue_head + 1) & EVENT_QUEUE_MASK;
            LeaveCriticalSection(&g_state.queue_lock);

            /* Wrap in RFC 5424 */
            FormatLogSyslogLine(syslog_line, MAX_SYSLOG_LINE, hostname, json_obj);
            HeapFree(GetProcessHeap(), 0, json_obj);

            size_t line_len = strlen(syslog_line);

            /* Thread-safe TCP send */
            EnterCriticalSection(&g_state.syslog_lock);
            send_ok = SyslogSendAll(syslog_line, line_len);
            if (!send_ok) {
                DisconnectSyslog();
                ShowNotification(NIIF_WARNING, APP_NAME,
                    L"Syslog TCP lost — reconnecting");
            } else {
                InterlockedIncrement64(&g_state.events_sent);
            }
            LeaveCriticalSection(&g_state.syslog_lock);
        }

        last_flush = GetTickCount();
    }

    /* Drain on shutdown */
    EnterCriticalSection(&g_state.syslog_lock);
    while (g_state.event_queue_head != g_state.event_queue_tail) {
        char* json_obj = g_state.event_queue[g_state.event_queue_head];
        size_t json_len = g_state.event_queue_lens[g_state.event_queue_head];
        g_state.event_queue_head = (g_state.event_queue_head + 1) & EVENT_QUEUE_MASK;
        if (json_obj && g_state.syslog_connected) {
            FormatLogSyslogLine(syslog_line, MAX_SYSLOG_LINE, hostname, json_obj);
            SyslogSendAll(syslog_line, strlen(syslog_line));
        }
        HeapFree(GetProcessHeap(), 0, json_obj);
    }
    LeaveCriticalSection(&g_state.syslog_lock);

    DisconnectSyslog();
    HeapFree(GetProcessHeap(), 0, syslog_line);
    return 0;
}

static DWORD WINAPI MetricsThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    HTTP_CLIENT* client = HttpClientCreate(
        g_state.backend_url, g_state.backend_token, g_state.tls_verify);
    if (!client) return 1;

    while (!g_state.shutdown) {
        /* Sleep metrics_interval, waking every second to check shutdown */
        int i;
        for (i = 0; i < g_state.metrics_interval && !g_state.shutdown; i++)
            Sleep(1000);
        if (g_state.shutdown) break;

        if (g_state.endpoint_id <= 0) continue; /* not registered yet */

        MetricsPayload mp;
        if (!CollectMetrics(&mp)) continue;

        /* Build metrics JSON matching Python MetricPayload model */
        char json_buf[1024];
        JsonBuilder jb;
        JsonInit(&jb, json_buf, sizeof(json_buf));
        JsonObjectBegin(&jb);
        JsonDouble(&jb, "cpu_usage",      mp.cpu_usage,      2);
        JsonDouble(&jb, "memory_usage",   mp.memory_usage,   2);
        JsonDouble(&jb, "disk_usage",     mp.disk_usage,     2);
        JsonDouble(&jb, "uptime_seconds", mp.uptime_seconds, 2);
        JsonInt   (&jb, "process_count",  mp.process_count);
        JsonStr   (&jb, "metric_source",  "agent");
        JsonStr   (&jb, "collected_at",   mp.collected_at);
        JsonObjectEnd(&jb);
        JsonFinish(&jb);

        char path[64];
        StringCchPrintfA(path, sizeof(path),
            "/monitoring/endpoints/%d/metrics", g_state.endpoint_id);

        int status = 0;
        if (HttpPost(client, path, json_buf, NULL, 0, &status))
            InterlockedIncrement64(&g_state.metrics_sent);
    }

    HttpClientDestroy(client);
    return 0;
}

static DWORD WINAPI LogReaderThread(LPVOID param)
{
    UNREFERENCED_PARAMETER(param);

    if (g_state.log_reader_cfg.count == 0) return 0;

    /* Stack buffer for per-entry JSON */
    char json_buf[MAX_EVENT_JSON];

    while (!g_state.shutdown) {
        /* Sleep log_interval, check shutdown every second */
        for (int i = 0; i < g_state.log_interval && !g_state.shutdown; i++)
            Sleep(1000);
        if (g_state.shutdown) break;

        LRLogBatch batch;
        batch.count = 0;
        if (!ReadNewLogs(&g_state.log_reader_cfg, g_state.endpoint_id, &batch))
            continue;
        if (batch.count == 0) continue;

        /* Enqueue each entry into the shared ring buffer — EventWorkerThread
           ships them over TCP syslog together with Windows events */
        for (int i = 0; i < batch.count; i++) {
            FormatLREntryJson(json_buf, sizeof(json_buf), &batch.entries[i]);
            size_t len = strlen(json_buf);
            if (len > 0) EnqueueLogJson(json_buf, len);
        }
    }

    return 0;
}

/* ------------------------------------------------------------------ */
/*  Status dialog                                                     */
/* ------------------------------------------------------------------ */

#define IDC_STATUS_LABEL    3001
#define IDC_STATUS_TEXT     3002
#define IDC_CLOSE_BTN       3003

static void UpdateStatusText(HWND hdlg)
{
    char text[4096];
    DWORD uptime_s = (GetTickCount() - g_state.start_tick) / 1000;
    DWORD hours   = uptime_s / 3600;
    DWORD minutes = (uptime_s % 3600) / 60;
    DWORD seconds = uptime_s % 60;

    const char* token_status = g_state.backend_token[0]
        ? "Configured" : "NOT CONFIGURED";
    const char* syslog_status = g_state.syslog_connected ? "CONNECTED" : "DISCONNECTED";

    StringCchPrintfA(text, sizeof(text),
        "TechvSOC XDR Native Agent v%s\r\n\r\n"
        "Backend URL:\t%s\r\n"
        "Token:\t\t%s\r\n"
        "Endpoint ID:\t%d\r\n"
        "Syslog TCP:\t\t%s:%s (%s)\r\n\r\n"
        "Events Collected:\t%lld\r\n"
        "Events Sent:\t%lld\r\n"
        "Metrics Sent:\t%lld\r\n"
        "Uptime:\t\t%02lu:%02lu:%02lu\r\n"
        "Channels Active:\t%d / %d\r\n\r\n"
        "Active Channels:\r\n",
        g_state.agent_version,
        g_state.backend_url,
        token_status,
        g_state.endpoint_id,
        g_state.syslog_host, g_state.syslog_port, syslog_status,
        (long long)g_state.events_collected,
        (long long)g_state.events_sent,
        (long long)g_state.metrics_sent,
        hours, minutes, seconds,
        g_state.sub_count, (int)CHANNEL_COUNT);

    int offset = (int)strlen(text);
    int i;
    for (i = 0; i < (int)CHANNEL_COUNT && offset < (int)sizeof(text) - 260; i++) {
        if (g_state.channel_active[i]) {
            char entry[256];
            StringCchPrintfA(entry, sizeof(entry), "  [*] %S (%S)\r\n",
                g_channel_entries[i].name,
                g_channel_entries[i].category ? g_channel_entries[i].category : L"General");
            StringCchCatA(text, sizeof(text), entry);
            offset += (int)strlen(entry);
        }
    }

    SetDlgItemTextA(hdlg, IDC_STATUS_TEXT, text);
}

static INT_PTR CALLBACK StatusDlgProc(HWND hdlg, UINT msg,
                                       WPARAM wp, LPARAM lp)
{
    UNREFERENCED_PARAMETER(lp);
    switch (msg) {
    case WM_INITDIALOG:
        SetTimer(hdlg, IDT_STATUS_TIMER, STATUS_INTERVAL, NULL);
        UpdateStatusText(hdlg);
        return TRUE;

    case WM_TIMER:
        if (wp == IDT_STATUS_TIMER) {
            UpdateStatusText(hdlg);
        }
        return TRUE;

    case WM_COMMAND:
        if (LOWORD(wp) == IDC_CLOSE_BTN || LOWORD(wp) == IDCANCEL) {
            KillTimer(hdlg, IDT_STATUS_TIMER);
            g_state.status_dialog = NULL;
            EndDialog(hdlg, 0);
            return TRUE;
        }
        break;

    case WM_CLOSE:
        KillTimer(hdlg, IDT_STATUS_TIMER);
        g_state.status_dialog = NULL;
        EndDialog(hdlg, 0);
        return TRUE;
    }
    return FALSE;
}

static void ShowStatusDialog(HINSTANCE inst)
{
    if (g_state.status_dialog && IsWindow(g_state.status_dialog)) {
        SetForegroundWindow(g_state.status_dialog);
        return;
    }

    struct {
        DLGTEMPLATE dlg;
        WORD menu;
        WORD cls;
        WORD title;
    } tmpl;

    memset(&tmpl, 0, sizeof(tmpl));
    tmpl.dlg.style = WS_POPUP | WS_CAPTION | WS_SYSMENU |
                     DS_MODALFRAME | DS_CENTER;
    tmpl.dlg.cx = 340;
    tmpl.dlg.cy = 220;
    tmpl.dlg.x  = 0;
    tmpl.dlg.y  = 0;
    tmpl.menu   = 0;
    tmpl.cls    = 0;
    tmpl.title  = 0;

    g_state.status_dialog = CreateDialogIndirectParamW(
        inst, &tmpl.dlg, NULL, StatusDlgProc, 0);

    if (g_state.status_dialog) {
        SetWindowTextW(g_state.status_dialog, L"TechvSOC XDR Agent - Status");

        RECT rc;
        GetClientRect(g_state.status_dialog, &rc);

        CreateWindowExW(0, L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE |
            ES_AUTOVSCROLL | ES_READONLY,
            10, 10, rc.right - 20, rc.bottom - 50,
            (HWND)g_state.status_dialog, (HMENU)(LONG_PTR)IDC_STATUS_TEXT,
            inst, NULL);

        CreateWindowExW(0, L"BUTTON", L"Close",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            rc.right / 2 - 40, rc.bottom - 35, 80, 25,
            (HWND)g_state.status_dialog, (HMENU)(LONG_PTR)IDC_CLOSE_BTN,
            inst, NULL);

        HFONT hfont = CreateFontW(14, 0, 0, 0, FW_NORMAL, FALSE, FALSE,
                                   FALSE, DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                                   CLIP_DEFAULT_PRECIS, FIXED_PITCH,
                                   FF_MODERN, L"Consolas");
        SendDlgItemMessageW(g_state.status_dialog, IDC_STATUS_TEXT,
                             WM_SETFONT, (WPARAM)hfont, TRUE);

        ShowWindow(g_state.status_dialog, SW_SHOW);
        UpdateWindow(g_state.status_dialog);
    }
}

/* ------------------------------------------------------------------ */
/*  Tray icon & context menu                                          */
/* ------------------------------------------------------------------ */

static void ShowNotification(DWORD icon_type, const WCHAR* title, const WCHAR* text)
{
    if (!g_state.nid.hWnd) return;

    g_state.nid.uFlags    |= NIF_INFO;
    g_state.nid.dwInfoFlags = icon_type;

    StringCchCopyW(g_state.nid.szInfoTitle,
                    sizeof(g_state.nid.szInfoTitle) / sizeof(WCHAR),
                    title ? title : APP_NAME);
    StringCchCopyW(g_state.nid.szInfo,
                    sizeof(g_state.nid.szInfo) / sizeof(WCHAR),
                    text ? text : L"");

    Shell_NotifyIconW(NIM_MODIFY, &g_state.nid);
}

static BOOL AddTrayIcon(void)
{
    HICON hAppIcon = LoadIcon(GetModuleHandleW(NULL),
                               MAKEINTRESOURCE(IDI_APP_ICON));
    if (!hAppIcon) {
        hAppIcon = LoadIconW(NULL, IDI_SHIELD);
    }

    memset(&g_state.nid, 0, sizeof(g_state.nid));
    g_state.nid.cbSize           = sizeof(NOTIFYICONDATAW);
    g_state.nid.hWnd             = g_state.msg_window;
    g_state.nid.uID              = 1;
    g_state.nid.uFlags           = NIF_ICON | NIF_TIP | NIF_MESSAGE | NIF_INFO;
    g_state.nid.uCallbackMessage = WM_TRAYICON;
    g_state.nid.hIcon            = hAppIcon;
    g_state.nid.dwInfoFlags      = NIIF_NONE;
    StringCchCopyW(g_state.nid.szTip, sizeof(g_state.nid.szTip) / sizeof(WCHAR),
                    APP_NAME);

    return Shell_NotifyIconW(NIM_ADD, &g_state.nid);
}

static void RemoveTrayIcon(void)
{
    Shell_NotifyIconW(NIM_DELETE, &g_state.nid);
}

static void ShowContextMenu(HWND hwnd)
{
    if (!g_state.tray_menu) {
        g_state.tray_menu = CreatePopupMenu();
        if (!g_state.tray_menu) return;
        AppendMenuW(g_state.tray_menu, MF_STRING, IDM_SHOW_STATUS,
                     L"Show Status");
        AppendMenuW(g_state.tray_menu, MF_STRING, IDM_RESTART,
                     L"Restart Collection");
        AppendMenuW(g_state.tray_menu, MF_SEPARATOR, 0, NULL);
        AppendMenuW(g_state.tray_menu, MF_STRING, IDM_EXIT, L"Exit");
    }

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(g_state.tray_menu, TPM_RIGHTBUTTON,
                    pt.x, pt.y, 0, hwnd, NULL);
}

/* ------------------------------------------------------------------ */
/*  Message-only window procedure                                     */
/* ------------------------------------------------------------------ */

static LRESULT CALLBACK WndProc(HWND hwnd, UINT msg,
                                 WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_TRAYICON:
        switch (LOWORD(lp)) {
        case WM_RBUTTONUP:
        case WM_CONTEXTMENU:
            ShowContextMenu(hwnd);
            break;
        case WM_LBUTTONDBLCLK:
            ShowStatusDialog((HINSTANCE)GetModuleHandleW(NULL));
            break;
        }
        return 0;

    case WM_COMMAND:
        switch (LOWORD(wp)) {
        case IDM_SHOW_STATUS:
            ShowStatusDialog((HINSTANCE)GetModuleHandleW(NULL));
            break;
        case IDM_RESTART:
            /* Stop and restart subscriptions */
            StopSubscriptions();
            StartSubscriptions();
            break;
        case IDM_EXIT:
            PostQuitMessage(0);
            break;
        }
        return 0;

    case WM_DESTROY:
        RemoveTrayIcon();
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProcW(hwnd, msg, wp, lp);
}

static BOOL RegisterWindowClass(HINSTANCE inst)
{
    WNDCLASSEXW wc;
    memset(&wc, 0, sizeof(wc));
    wc.cbSize        = sizeof(wc);
    wc.lpfnWndProc   = WndProc;
    wc.hInstance      = inst;
    wc.lpszClassName  = APP_CLASS;

    return (RegisterClassExW(&wc) != 0);
}

static BOOL CreateMessageWindow(HINSTANCE inst)
{
    g_state.msg_window = CreateWindowExW(
        0, APP_CLASS, L"TechvSOCEventForwarder",
        0, 0, 0, 0, 0,
        HWND_MESSAGE,    /* message-only window */
        NULL, inst, NULL);

    return (g_state.msg_window != NULL);
}

/* ------------------------------------------------------------------ */
/*  Initialization and cleanup                                        */
/* ------------------------------------------------------------------ */

static BOOL Initialize(HINSTANCE inst)
{
    memset(&g_state, 0, sizeof(g_state));

    InitializeCriticalSection(&g_state.queue_lock);
    InitializeCriticalSection(&g_state.syslog_lock);
    g_state.syslog_sock = INVALID_SOCKET;
    g_state.queue_event = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_state.queue_event) {
        return FALSE;
    }

    g_state.start_tick = GetTickCount();

    /* Load configuration */
    if (!LoadConfiguration()) {
        ShowNotification(NIIF_ERROR, APP_NAME,
            L"Fatal: Failed to load configuration");
        return FALSE;
    }

    if (!InitializeWinsock()) {
        return FALSE;
    }

    /* Register window class and create message window */
    if (!RegisterWindowClass(inst)) {
        return FALSE;
    }

    if (!CreateMessageWindow(inst)) {
        return FALSE;
    }

    /* Add system tray icon */
    if (!AddTrayIcon()) {
        /* Non-fatal — continue without tray icon */
    }

    /* Start event subscriptions */
    if (!StartSubscriptions()) {
        /* At least one channel should work; if none, still run */
    }

    /* Show notification with active channel count */
    {
        WCHAR msg[256];
        StringCchPrintfW(msg, 256, L"Monitoring %d event channels",
            g_state.sub_count);
        ShowNotification(NIIF_INFO, APP_NAME, msg);
    }

    /* Register endpoint if not already registered */
    if (g_state.endpoint_id <= 0 && g_state.backend_token[0]) {
        HTTP_CLIENT* reg_client = HttpClientCreate(
            g_state.backend_url, g_state.backend_token, g_state.tls_verify);
        if (reg_client) {
            int id = RegisterEndpoint(reg_client);
            HttpClientDestroy(reg_client);
            if (id > 0) {
                g_state.endpoint_id = id;
                SaveEndpointId(id);
                WCHAR msg[256];
                StringCchPrintfW(msg, 256, L"Registered as endpoint ID %d", id);
                ShowNotification(NIIF_INFO, APP_NAME, msg);
            }
        }
    }

    /* Start event worker thread */
    g_state.shutdown = 0;
    g_state.event_worker_thread = CreateThread(NULL, 0, EventWorkerThread, NULL, 0, NULL);
    if (!g_state.event_worker_thread) {
        StopSubscriptions();
        RemoveTrayIcon();
        return FALSE;
    }

    /* Start metrics thread (only if token configured) */
    if (g_state.backend_token[0]) {
        g_state.metrics_thread = CreateThread(NULL, 0, MetricsThread, NULL, 0, NULL);
    }

    /* Start log reader thread (only if log files configured and token present) */
    if (g_state.log_reader_cfg.count > 0 && g_state.backend_token[0]) {
        g_state.log_reader_thread = CreateThread(NULL, 0, LogReaderThread, NULL, 0, NULL);
    }

    return TRUE;
}

static void Cleanup(void)
{
    /* Signal shutdown and wake worker */
    InterlockedExchange(&g_state.shutdown, 1);
    SetEvent(g_state.queue_event);

    /* Wait for all threads */
    HANDLE threads[3];
    int t_count = 0;
    if (g_state.event_worker_thread) threads[t_count++] = g_state.event_worker_thread;
    if (g_state.metrics_thread)      threads[t_count++] = g_state.metrics_thread;
    if (g_state.log_reader_thread)   threads[t_count++] = g_state.log_reader_thread;
    if (t_count) WaitForMultipleObjects(t_count, threads, TRUE, 10000);

    /* Close handles */
    if (g_state.event_worker_thread) { CloseHandle(g_state.event_worker_thread); g_state.event_worker_thread = NULL; }
    if (g_state.metrics_thread)      { CloseHandle(g_state.metrics_thread);      g_state.metrics_thread      = NULL; }
    if (g_state.log_reader_thread)   { CloseHandle(g_state.log_reader_thread);   g_state.log_reader_thread   = NULL; }

    /* Save bookmarks and stop subscriptions */
    StopSubscriptions();

    /* Remove tray icon */
    RemoveTrayIcon();

    /* Drain event queue */
    EnterCriticalSection(&g_state.queue_lock);
    while (g_state.event_queue_head != g_state.event_queue_tail) {
        HeapFree(GetProcessHeap(), 0, g_state.event_queue[g_state.event_queue_head]);
        g_state.event_queue_head = (g_state.event_queue_head + 1) & EVENT_QUEUE_MASK;
    }
    LeaveCriticalSection(&g_state.queue_lock);
    DeleteCriticalSection(&g_state.queue_lock);
    DisconnectSyslog();
    DeleteCriticalSection(&g_state.syslog_lock);
    CleanupWinsock();
    if (g_state.queue_event) { CloseHandle(g_state.queue_event); g_state.queue_event = NULL; }

    /* Destroy menu */
    if (g_state.tray_menu) {
        DestroyMenu(g_state.tray_menu);
        g_state.tray_menu = NULL;
    }

    /* Destroy message window */
    if (g_state.msg_window) {
        DestroyWindow(g_state.msg_window);
        g_state.msg_window = NULL;
    }
}

/* ------------------------------------------------------------------ */
/*  WinMain entry point                                               */
/* ------------------------------------------------------------------ */

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                    LPSTR lpCmdLine, int nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);
    UNREFERENCED_PARAMETER(nCmdShow);

    /* Prevent multiple instances */
    HANDLE mutex = CreateMutexW(NULL, TRUE, L"TechvSOCEventForwarderMutex");
    if (GetLastError() == ERROR_ALREADY_EXISTS) {
        CloseHandle(mutex);
        return 1;
    }

    /* Initialize */
    if (!Initialize(hInstance)) {
        CloseHandle(mutex);
        return 1;
    }

    /* Message loop */
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (g_state.status_dialog && IsDialogMessageW(g_state.status_dialog, &msg)) {
            continue;
        }
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }

    /* Cleanup */
    Cleanup();

    ReleaseMutex(mutex);
    CloseHandle(mutex);

    return 0;
}
