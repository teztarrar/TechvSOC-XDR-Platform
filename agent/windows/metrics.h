#pragma once
/*
 * metrics.h - Windows system metrics collection for TechvSOC XDR Agent
 * TechvSOC XDR Platform
 *
 * No PDH dependency. Uses GetSystemTimes (CPU), GlobalMemoryStatusEx (RAM),
 * GetDiskFreeSpaceEx (disk), GetTickCount64 (uptime),
 * CreateToolhelp32Snapshot (process count).
 */

#include <windows.h>

/* ------------------------------------------------------------------ */
/*  Metrics payload                                                   */
/* ------------------------------------------------------------------ */

typedef struct {
    double cpu_usage;        /* 0.0-100.0 -- sampled over ~200 ms          */
    double memory_usage;     /* 0.0-100.0 -- physical memory used percent  */
    double disk_usage;       /* 0.0-100.0 -- C:\ used percent              */
    double uptime_seconds;   /* seconds since last system boot             */
    int    process_count;    /* total live process count                   */
    char   collected_at[32]; /* ISO8601 UTC: "2024-01-15T12:34:56.000Z"   */
} MetricsPayload;

/* ------------------------------------------------------------------ */
/*  Public API                                                        */
/* ------------------------------------------------------------------ */

/*
 * CollectMetrics - fill all fields.
 * Blocks for ~200 ms internally (CPU sampling window).
 * Returns TRUE on success (all fields valid).
 */
BOOL CollectMetrics(MetricsPayload* out);
