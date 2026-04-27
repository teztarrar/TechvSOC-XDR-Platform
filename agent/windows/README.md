# TechvSOC XDR Native Windows Agent

A high-performance, native C agent for the TechvSOC XDR Platform. Runs as a background process with a system tray icon, forwarding Windows Event Log channels, file-based logs, and system metrics to a centralized backend.

## Features

- **Windows Event Log forwarding** -- subscribes to 28 event channels (Security, System, Application, Sysmon, PowerShell, Defender, RDP, Firewall, Kerberos, NTLM, SMB, DNS, and more) using the Event Tracing for Windows (ETW) API
- **File log tailing** -- monitors up to 32 log files with offset persistence, auto-detects log rotation, infers severity from content keywords
- **System metrics collection** -- CPU, memory, disk usage, uptime, process count (no PDH dependency)
- **Dual transport** -- events ship over raw TCP syslog (RFC 5424) for low-latency log delivery; metrics and endpoint registration use HTTPS REST with JWT Bearer auth
- **Event bookmarking** -- resumes from the last processed event across restarts
- **Configurable filtering** -- filter Security events by Event ID, filter by provider name (McAfee, Microsoft Antimalware, etc.)
- **System tray interface** -- custom app icon, balloon notifications for connection status, right-click context menu (Show Status, Restart Collection, Exit)
- **Single-instance** -- mutex prevents duplicate processes
- **Zero runtime dependencies** -- statically links all Windows APIs, no external DLLs required

## Prerequisites

- **Visual Studio 2022** (Community edition or higher) with the C/C++ desktop workload installed
- **Windows SDK** (included with VS 2022)
- No third-party libraries needed

## Building

### Option 1: Using the build script

Open a **x64 Developer Command Prompt for VS 2022** and run:

```
cd agent\windows
build.bat
```

This compiles all sources, embeds the app icon from `app.ico`, and produces `TechvSOCAgent.exe`.

### Option 2: Manual build from any terminal

If `cl.exe` is not in your PATH, initialize the MSVC environment first:

```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cd agent\windows
build.bat
```

### Option 3: One-liner from PowerShell / CMD

```
cmd /c """C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat"" x64 && cd /d D:\TechvSOC-XDR-Platform\agent\windows && build.bat"
```

### Build output

| File | Description |
|---|---|
| `TechvSOCAgent.exe` | The agent executable |
| `EventForwardingAggregator.exe` | Previous build artifact (can be deleted) |

## Project Files

| File | Purpose |
|---|---|
| `event_forwarder.c` | Main agent -- config loading, ETW subscriptions, syslog TCP client, event formatting, window/tray/message loop |
| `http_client.h` / `http_client.c` | Thread-safe WinHTTP REST client with 3x retry and exponential backoff |
| `json_builder.h` / `json_builder.c` | Stack-allocated JSON serializer (zero heap allocations, overflow-safe) |
| `metrics.h` / `metrics.c` | System metrics collector (CPU, RAM, disk, uptime, process count) |
| `log_reader.h` / `log_reader.c` | File log tailer with offset persistence and severity inference |
| `resource.h` / `resource.rc` / `app.ico` | Windows resource definitions and application icon |
| `event_forwarder.ini` | Agent configuration file |
| `event_forwarder.bm` | Bookmark state (auto-generated, stores last-read event positions) |
| `build.bat` | Build script |

## Configuration

Copy `event_forwarder.ini` to the same directory as `TechvSOCAgent.exe` and edit it. Key sections:

### `[syslog]` -- Log shipping endpoint

```ini
host = 127.0.0.1
port = 5514
```

The raw TCP syslog receiver. Must match the backend's `SYSLOG_TCP_PORT` (default `5514`).

### `[backend]` -- REST API

```ini
url = http://localhost:8000/api/v1
token = <your-jwt-token>
tls_verify = 1
```

- `token` is required for endpoint registration and metrics. Get it from the TechvSOC admin panel.
- Set `tls_verify = 0` for development with self-signed certificates.

### `[agent]` -- Agent behavior

```ini
version = 2.0.0
endpoint_id = 0
metrics_interval = 30      # seconds between metric reports
log_interval = 60           # seconds between file log scans
event_flush_interval = 10   # seconds between event queue flushes
event_flush_batch = 50      # flush after this many events
```

- `endpoint_id` is auto-populated after the first registration. Set to `0` for auto-register.
- Reduce `event_flush_interval` for more real-time forwarding. Increase `event_flush_batch` for higher throughput.

### `[log_files]` -- File log monitoring

```ini
count = 2
file_01 = C:\Logs\application.log
file_02 = C:\inetpub\logs\LogFiles\W3SVC1\u_ex.log
```

Set `count` to the number of files, then list each path. Up to 32 files supported.

### `[channels]` -- Windows Event Log channels

```ini
channel_01 = Security,enabled=1
channel_02 = System,enabled=1
channel_03 = Microsoft-Windows-Sysmon/Operational,enabled=1
```

Each line is `channel_path,enabled=1` or `channel_path,enabled=0`. Up to 32 channels.

Default configuration monitors: Security, System, Application, Sysmon, PowerShell, Windows Defender, Terminal Services/RDP (3 channels), Task Scheduler, Firewall, BITS, WMI, DNS Client, Print Service, Code Integrity, BitLocker, LSA, Security Auditing, SMB Client/Server, DHCP, NTLM, Kerberos, Windows Update, WinRM, Remote Access, Kernel General, File Replication.

### `[filters]` -- Event filtering

```ini
security_event_ids = 4624,4625,4634,4648,4672,4688,4697,4702,...
mcafee_provider = McLogEvent
ms_antimalware_provider = Microsoft Antimalware
eventlog_provider = Eventlog
```

Only forward Security channel events matching the listed Event IDs. Provider filters are applied to Application and System channels.

### `[logging]` -- Agent self-logging

```ini
log_level = 3     # 0=None, 1=Error, 2=Warning, 3=Info, 4=Debug
log_file = event_forwarder.log
```

## Running

1. Build the agent (see above)
2. Edit `event_forwarder.ini` -- set `[backend] url` and `token`
3. Place `event_forwarder.ini` in the same directory as `TechvSOCAgent.exe`
4. Run `TechvSOCAgent.exe`

The agent will:
- Appear in the system tray with the TechvSOC icon
- Show a balloon notification with the number of active channel subscriptions
- Warn if the backend token is not configured
- Auto-register with the backend and display the assigned endpoint ID
- Begin forwarding events and metrics

### System Tray Menu

Right-click the tray icon for:

| Option | Action |
|---|---|
| **Show Status** | Opens a dialog showing active channels, events collected, events sent, and queue depth |
| **Restart Collection** | Stops and restarts all event subscriptions |
| **Exit** | Gracefully shuts down: drains the event queue, saves bookmarks, disconnects |

### Multiple instances

The agent uses a named mutex (`TechvSOCEventForwarderMutex`). Only one instance can run at a time. Attempting to launch a second copy exits immediately.

## Architecture

```
                        Windows Event Log (ETW)
                              |
                         Subscriptions
                              |
                              v
    +-----------+     Event Queue (4096 ring buffer)
    | Log Files |---------^---|
    +-----------+         |   |
                          v   v
                    Event Worker Thread
                          |
              +-----------+-----------+
              |                       |
        TCP Syslog (RFC 5424)    Backend REST API
              |                  /       \
         [syslog]          Register    Metrics
                        endpoint    (CPU/RAM/Disk)
```

- **Event subscriptions** -- Each enabled channel gets an ETW subscription. Events are formatted as JSON and pushed into a lock-free ring buffer.
- **Event worker thread** -- Drains the queue, wraps events in RFC 5424 syslog frames, sends over TCP.
- **Metrics thread** -- Collects system metrics every `metrics_interval` seconds and POSTs to the backend.
- **Log reader thread** -- Tails configured files, infers severity, ships new lines over syslog TCP.
- **Message loop** -- Standard Windows message pump handles tray icon callbacks, context menu, and status dialog.

## State Files

The agent creates these files at runtime (in the same directory as the executable):

| File | Purpose |
|---|---|
| `event_forwarder.bm` | Bookmark positions for each event channel (enables resume after restart) |
| `event_forwarder_state.ini` | Stores the auto-assigned `endpoint_id` |
| `event_forwarder.log` | Agent log output (configurable via `[logging]`) |

## Troubleshooting

| Problem | Solution |
|---|---|
| `cl.exe not found` | Run from a Developer Command Prompt, or run `vcvarsall.bat x64` first |
| Build fails with linker errors | Ensure Windows SDK is installed (via VS Installer) |
| Agent exits immediately | Another instance is already running. Check system tray. |
| "Backend token not configured" warning | Edit `event_forwarder.ini` and set `[backend] token` |
| Events not appearing in backend | Check `[syslog] host` and `port` match the backend. Check `event_forwarder.log` for TCP errors. |
| Syslog TCP reconnecting repeatedly | Backend syslog receiver is not running or port is blocked. Check firewall rules. |
| Tray icon shows default shield | `app.ico` was not embedded during build. Rebuild with `build.bat`. |
