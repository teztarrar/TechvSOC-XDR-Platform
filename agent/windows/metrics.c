/*
 * metrics.c - Windows system metrics collection for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * Implements CollectMetrics(): CPU via GetSystemTimes two-sample delta,
 * RAM via GlobalMemoryStatusEx, disk via GetDiskFreeSpaceExW (C:\),
 * uptime via GetTickCount64, process count via Toolhelp32 snapshot.
 * No PDH, no CRT heap allocation.
 */

#pragma comment(lib, "kernel32.lib")

#include <windows.h>
#include <tlhelp32.h>
#include <strsafe.h>
#include "metrics.h"

/* ------------------------------------------------------------------ */
/*  Forward declarations                                              */
/* ------------------------------------------------------------------ */

static ULONGLONG FTtoU64(FILETIME ft);
static double    SampleCpuUsage(void);
static double    SampleMemoryUsage(void);
static double    SampleDiskUsage(void);
static double    SampleUptimeSeconds(void);
static int       SampleProcessCount(void);

/* ------------------------------------------------------------------ */
/*  Internal helpers                                                  */
/* ------------------------------------------------------------------ */

/*
 * FTtoU64 - convert FILETIME to 64-bit 100-nanosecond tick count.
 */
static ULONGLONG FTtoU64(FILETIME ft)
{
    ULARGE_INTEGER u;
    u.LowPart  = ft.dwLowDateTime;
    u.HighPart = ft.dwHighDateTime;
    return u.QuadPart;
}

/*
 * SampleCpuUsage - return CPU busy percentage over a ~200 ms window.
 * Uses two calls to GetSystemTimes bracketing a Sleep(200).
 * Formula: busy = (total - idle) / total across all logical CPUs.
 */
static double SampleCpuUsage(void)
{
    FILETIME idle0, kernel0, user0;
    FILETIME idle1, kernel1, user1;

    /* Snapshot t0 */
    if (!GetSystemTimes(&idle0, &kernel0, &user0)) {
        return 0.0;
    }

    Sleep(200);

    /* Snapshot t1 */
    if (!GetSystemTimes(&idle1, &kernel1, &user1)) {
        return 0.0;
    }

    /* Delta in 100-ns units across all logical CPUs */
    ULONGLONG kern_diff  = FTtoU64(kernel1) - FTtoU64(kernel0);
    ULONGLONG user_diff  = FTtoU64(user1)   - FTtoU64(user0);
    ULONGLONG idle_diff  = FTtoU64(idle1)   - FTtoU64(idle0);
    ULONGLONG total_diff = kern_diff + user_diff;

    double cpu = 0.0;
    if (total_diff > 0) {
        cpu = (1.0 - (double)idle_diff / (double)total_diff) * 100.0;
    }

    /* Clamp to [0.0, 100.0] */
    if (cpu < 0.0)   cpu = 0.0;
    if (cpu > 100.0) cpu = 100.0;

    return cpu;
}

/*
 * SampleMemoryUsage - return physical memory used percent (0-100).
 * GlobalMemoryStatusEx already exposes dwMemoryLoad as 0-100.
 */
static double SampleMemoryUsage(void)
{
    MEMORYSTATUSEX msx;
    msx.dwLength = sizeof(msx);
    if (!GlobalMemoryStatusEx(&msx)) {
        return 0.0;
    }
    return (double)msx.dwMemoryLoad;   /* already 0-100 */
}

/*
 * SampleDiskUsage - return C:\ used percent (0-100).
 * Uses GetDiskFreeSpaceExW; result = 1 - (free / total).
 */
static double SampleDiskUsage(void)
{
    ULARGE_INTEGER free_to_caller;
    ULARGE_INTEGER total_bytes;
    ULARGE_INTEGER free_bytes;

    if (!GetDiskFreeSpaceExW(L"C:\\",
                              &free_to_caller,
                              &total_bytes,
                              &free_bytes)) {
        return 0.0;
    }

    if (total_bytes.QuadPart == 0) {
        return 0.0;
    }

    double used = (1.0 - (double)free_bytes.QuadPart
                        / (double)total_bytes.QuadPart) * 100.0;

    /* Clamp to [0.0, 100.0] */
    if (used < 0.0)   used = 0.0;
    if (used > 100.0) used = 100.0;

    return used;
}

/*
 * SampleUptimeSeconds - return system uptime in seconds.
 * GetTickCount64 wraps after ~584 million years; safe for production.
 */
static double SampleUptimeSeconds(void)
{
    return (double)GetTickCount64() / 1000.0;
}

/*
 * SampleProcessCount - return total running process count via snapshot.
 * Uses Toolhelp32 TH32CS_SNAPPROCESS; counts every PROCESSENTRY32W entry.
 */
static int SampleProcessCount(void)
{
    int     count = 0;
    HANDLE  snap  = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (snap == INVALID_HANDLE_VALUE) {
        return 0;
    }

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    if (Process32FirstW(snap, &pe)) {
        do {
            count++;
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return count;
}

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/*
 * CollectMetrics - fill all fields of *out.
 * Blocks ~200 ms while sampling CPU.
 * Returns TRUE on success; all fields are valid on TRUE.
 * Returns FALSE only if out is NULL.
 */
BOOL CollectMetrics(MetricsPayload* out)
{
    if (!out) {
        return FALSE;
    }

    /* CPU -- this call blocks ~200 ms */
    out->cpu_usage = SampleCpuUsage();

    /* Memory */
    out->memory_usage = SampleMemoryUsage();

    /* Disk (C:\) */
    out->disk_usage = SampleDiskUsage();

    /* Uptime */
    out->uptime_seconds = SampleUptimeSeconds();

    /* Process count */
    out->process_count = SampleProcessCount();

    /* Timestamp -- ISO8601 UTC at moment of collection */
    SYSTEMTIME st;
    GetSystemTime(&st);
    StringCchPrintfA(out->collected_at, sizeof(out->collected_at),
        "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ",
        st.wYear, st.wMonth, st.wDay,
        st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);

    return TRUE;
}
