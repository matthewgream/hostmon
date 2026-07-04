# hostmon

Host / system monitor. Periodically samples the machine's runtime state and
static platform info and publishes it as structured JSON to an MQTT broker.

One of a small family of single-binary MQTT monitor daemons that share a common
structure and config convention:

- **hostmon** — this host's system + platform metrics
- **connmon** — outbound connectivity (UPnP port maps, reachability, dynamic DNS)
- **trafmon** — per-interface network traffic counters (via SNMP)

## What it does

On two independent timers it publishes two payload *types*:

- **`system`** (default every 5 min) — dynamic runtime metrics: uptime, load,
  CPU temp/frequency/governor, memory, per-interface network counters, disk
  usage, monitored process up/down, time sync, default-gateway ping, DNS
  resolution, and per-topic MQTT freshness/rate stats.
- **`platform`** (default once a day) — slow-changing host facts: architecture,
  OS, boot info, hardware identifiers, etc.

Optional health checks (processes, time sync, gateway ping, DNS resolve, MQTT
topic activity) are folded into the `system` payload so a collector can alarm
on them.

## Build

Single C source (`hostmon.c`) plus headers in the source tree; no runtime deps
beyond an MQTT broker.

    make                    # native build
    make install-dev-armhf  # (implies) cross-compile for 32-bit ARM (armhf)
    make format             # clang-format the source
    make test               # build and run against the local .cfg
    make clean

`hostinfo.js` is a Node companion viewer (see below); it needs `npm i mqtt`.

## Install

**Host-specific config convention:** the Makefile installs
`hostmon.<hostname>.cfg` if it exists, otherwise falls back to the generic
`hostmon.cfg`. Commit one config per deployment host (e.g.
`hostmon.bastu.cfg`) alongside the documented default `hostmon.cfg`.

    make install-dev          # native:  binary -> /usr/local/bin/hostmon
                              #          config -> /etc/default/hostmon
                              #          unit   -> hostmon.service (enabled)
    make install-dev-armhf    # same, from the armhf cross-build
    make remove-dev           # uninstall

Runs as the systemd service `hostmon.service`; runtime config is
`/etc/default/hostmon`.

## Configuration

Every setting is a config-file `key=value` **and** an equivalent `--key value`
command-line flag. `--config <file>` selects the file (default `hostmon.cfg`).
`hostmon --help` lists everything.

### MQTT (common to hostmon / connmon / trafmon)

| key | default | meaning |
|---|---|---|
| `mqtt-server` | `mqtt://localhost` | broker URL |
| `mqtt-client` | `hostmon` | client id |
| `mqtt-topic-prefix` | `system/monitor` | base topic |
| `mqtt-tls-insecure` | `false` | skip TLS cert verification |
| `mqtt-reconnect-delay` | `5` | reconnect backoff start (s) |
| `mqtt-reconnect-delay-max` | `60` | reconnect backoff cap (s) |

### hostmon-specific

| key | default | meaning |
|---|---|---|
| `mqtt-topic-hostname` | `true` | append `/<hostname>` to the topic |
| `mqtt-topic-per-type` | `false` | publish to `<prefix>/system` and `<prefix>/platform` instead of one topic carrying a `type` field |
| `interval-system` | `300` | `system` payload period (s) |
| `interval-platform` | `86400` | `platform` payload period (s) |
| `check-processes` | *(none)* | comma-separated process names to report up/down |
| `check-timesync` | `true` | report time-sync status |
| `check-gateway` | `true` | ping the default gateway |
| `check-resolve` | *(none)* | DNS host to resolve as a reachability check |
| `check-topics` | *(none)* | `[server;]topic1,topic2,…` — report freshness/rates of these MQTT topics |
| `debug` | `false` | verbose logging |

## Output (MQTT)

By default publishes to **`<mqtt-topic-prefix>/<hostname>`** with a `type` field
(`system` or `platform`). With `mqtt-topic-per-type=true` it splits into
`<prefix>/system` and `<prefix>/platform` instead.

Example (`system` payload, trimmed):

```
$ mosquitto_sub -t 'system/monitor/#'
{ "timestamp":"2026-07-04T11:34:44Z", "type":"system", "uptime_secs":93729,
  "uptime":"1d 2h 2m", "load":{"1min":0.25,"5min":0.23,"15min":0.16},
  "cpu":{"temp_c":19.9,"governor":"ondemand"}, "memory":{"total_kb":496132,"available_kb":343932},
  "network":[{"name":"end0","up":true,"ip":"192.168.0.226","rx_bytes":…,"tx_bytes":…}],
  "processes":[{"name":"mosquitto","running":true},{"name":"node","running":true}],
  "disk":{"total_mb":3996,"used_mb":1186}, "timesync":{"synchronized":true},
  "gateway":{"ip":"192.168.0.1","reachable":true,"rtt_ms":13.7},
  "resolve":{"hostname":"google.com","ok":true},
  "topics":[{"topic":"rs485/a/#","last_message_time":"…","rates":{…}}] }
```

## Companion tool: `hostinfo.js`

Subscribes to the broker and renders hostmon data as readable tables.

    hostinfo [--platform|--system] [--detailed] [--server mqtt://host:port] [host...]

Env overrides: `MQTT_SERVER`, `HOSTMON_TOPIC`.

## License

CC BY-NC-SA 4.0 — see [LICENSE](LICENSE).
