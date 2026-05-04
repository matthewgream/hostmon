#!/usr/bin/env node

// hostinfo — display hostmon MQTT data in table format
// Usage: hostinfo [--platform|--system] [--detailed] [--server mqtt://host:port] [--timeout ms] [host...]

'use strict';

const mqtt = require('mqtt');

// -----------------------------------------------------------------------------------------------------------------------------------------

const args = process.argv.slice(2);
const opts = {
    mode: 'system',
    detailed: false,
    server: process.env.MQTT_SERVER || 'mqtt://localhost:1883',
    topic: process.env.HOSTMON_TOPIC || 'system/monitor/#',
    timeout: 2000,
    hosts: [],
};

for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--platform' || a === '-p') opts.mode = 'platform';
    else if (a === '--system' || a === '-s') opts.mode = 'system';
    else if (a === '--detailed' || a === '-d') opts.detailed = true;
    else if (a === '--server' && args[i + 1]) opts.server = args[++i];
    else if (a === '--topic' && args[i + 1]) opts.topic = args[++i];
    else if (a === '--timeout' && args[i + 1]) opts.timeout = parseInt(args[++i], 10);
    else if (a === '--help' || a === '-h') {
        console.log(`Usage: hostinfo [OPTIONS] [host...]

Options:
  --platform, -p    Show platform (static) info
  --system, -s      Show system (dynamic) info (default)
  --detailed, -d    Show detailed output
  --server URL      MQTT server (default: mqtt://localhost:1883)
  --topic TOPIC     MQTT topic (default: system/monitor/#)
  --timeout MS      Wait time for retained messages (default: 2000)
  --help, -h        Show this help

Arguments:
  host...           Filter by hostname prefix(es)`);
        process.exit(0);
    } else if (!a.startsWith('-')) opts.hosts.push(a.toLowerCase());
    else {
        console.error(`Unknown option: ${a}`);
        process.exit(1);
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

const data = {}; // { hostname: { platform: {}, system: {} } }

function onMessage(topic, payload) {
    const parts = topic.split('/');
    if (parts.length < 3) return;
    const hostname = parts[parts.length - 2];
    const type = parts[parts.length - 1];
    if (type !== 'platform' && type !== 'system') return;
    if (opts.hosts.length > 0 && !opts.hosts.some((h) => hostname.toLowerCase().startsWith(h))) return;
    try {
        if (!data[hostname]) data[hostname] = {};
        data[hostname][type] = JSON.parse(payload.toString());
    } catch (_) {
        /* ignore parse errors */
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

function stripAnsi(s) { return s.replace(/\x1b\[[0-9;]*m/g, ''); }
function visLen(s) { return stripAnsi(String(s)).length; }
function pad(s, n, right) {
    s = String(s ?? '');
    const vl = visLen(s);
    if (vl > n) {
        // truncate respecting ANSI: strip, truncate, re-add reset
        const plain = stripAnsi(s);
        return plain.substring(0, n - 1) + '…' + C.reset;
    }
    const fill = ' '.repeat(n - vl);
    return right ? fill + s : s + fill;
}
function rpad(s, n) {
    return pad(s, n, true);
}

function ago(secs) {
    if (secs == null) return '-';
    const d = Math.floor(secs / 86400),
        h = Math.floor((secs % 86400) / 3600),
        m = Math.floor((secs % 3600) / 60);
    if (d > 0) return `${d}d ${h}h`;
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
}

function fmtBytes(b) {
    if (b == null) return '-';
    if (b >= 1e9) return (b / 1e9).toFixed(1) + 'G';
    if (b >= 1e6) return (b / 1e6).toFixed(1) + 'M';
    if (b >= 1e3) return (b / 1e3).toFixed(1) + 'K';
    return String(b);
}

function fmtKb(kb) {
    if (kb == null) return '-';
    if (kb >= 1048576) return (kb / 1048576).toFixed(1) + 'G';
    if (kb >= 1024) return (kb / 1024).toFixed(0) + 'M';
    return kb + 'K';
}

function fmtPct(v) {
    return v != null ? v.toFixed(1) + '%' : '-';
}

function fmtTemp(v) {
    return v != null ? v.toFixed(1) + '°C' : '-';
}

function fmtFreq(khz) {
    if (khz == null) return '-';
    return (khz / 1000).toFixed(0) + 'MHz';
}

function timeAge(ts) {
    if (!ts) return '-';
    const d = new Date(ts);
    const secs = Math.floor((Date.now() - d.getTime()) / 1000);
    return ago(secs) + ' ago';
}

const SEP = '─';
const COLOURS = {
    reset: '\x1b[0m',
    dim: '\x1b[2m',
    bold: '\x1b[1m',
    red: '\x1b[31m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    cyan: '\x1b[36m',
};
const C = process.stdout.isTTY ? COLOURS : Object.fromEntries(Object.keys(COLOURS).map((k) => [k, '']));

function indicator(ok) {
    return ok ? `${C.green}✓${C.reset}` : `${C.red}✗${C.reset}`;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// Platform display
// -----------------------------------------------------------------------------------------------------------------------------------------

function showPlatformSummary(hosts) {
    const cols = [
        ['HOST', 22],
        ['ARCH', 8],
        ['KERNEL', 24],
        ['OS', 30],
        ['BOOT', 12],
        ['IFACES', 20],
        ['VERSION', 8],
    ];
    const hdr = cols.map(([n, w]) => pad(n, w)).join('  ');
    console.log(`${C.bold}${hdr}${C.reset}`);
    console.log(SEP.repeat(hdr.length));

    for (const [hostname, d] of hosts) {
        const p = d.platform || {};
        const ifaces = (p.interfaces || []).map((i) => `${i.name}(${i.mac || '?'})`).join(', ');
        console.log(
            [
                pad(hostname, cols[0][1]),
                pad(p.arch, cols[1][1]),
                pad(p.kernel, cols[2][1]),
                pad(p.os_pretty, cols[3][1]),
                pad(timeAge(p.boot_time), cols[4][1]),
                pad(ifaces, cols[5][1]),
                pad(p.hostmon_version, cols[6][1]),
            ].join('  ')
        );
    }
}

function showPlatformDetailed(hosts) {
    for (const [hostname, d] of hosts) {
        const p = d.platform || {};
        console.log(`${C.bold}${C.cyan}═══ ${hostname} ═══${C.reset}`);
        console.log(`  Hostname:     ${p.hostname || '-'}`);
        console.log(`  Version:      ${p.hostmon_version || '-'}`);
        console.log(`  OS:           ${p.os_pretty || p.os || '-'}`);
        console.log(`  Kernel:       ${p.kernel || '-'} (${p.kernel_version || ''})`);
        console.log(`  Arch:         ${p.arch || '-'}`);
        console.log(`  Boot time:    ${p.boot_time || '-'} (${timeAge(p.boot_time)})`);
        console.log(`  Timestamp:    ${p.timestamp || '-'}`);
        if (p.interfaces && p.interfaces.length > 0) {
            console.log(`  Interfaces:`);
            for (const i of p.interfaces) console.log(`    ${i.name}: type=${i.type}, mac=${i.mac || '?'}`);
        }
        console.log('');
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// System display
// -----------------------------------------------------------------------------------------------------------------------------------------

function showSystemSummary(hosts) {
    const cols = [
        ['HOST', 22],
        ['UPTIME', 8],
        ['CPU', 8],
        ['LOAD', 6],
        ['MEM', 12],
        ['SWAP', 7],
        ['DISK', 10],
        ['NET', 14],
        ['MQTT', 5],
        ['NTP', 4],
        ['GW', 8],
        ['DNS', 4],
    ];
    const hdr = cols.map(([n, w]) => pad(n, w)).join('  ');
    console.log(`${C.bold}${hdr}${C.reset}`);
    console.log(SEP.repeat(hdr.length));

    for (const [hostname, d] of hosts) {
        const s = d.system || {};
        const mem = s.memory || {};
        const cpu = s.cpu || {};
        const disk = s.disk || {};
        const gw = s.gateway || {};
        const resolve = s.resolve || {};
        const mq = s.mqtt || {};
        const ts = s.timesync || {};

        const nets = s.network || [];
        const netStr = nets
            .map((n) => {
                let st = n.up ? `${n.name}↑` : `${C.red}${n.name}↓${C.reset}`;
                return st;
            })
            .join(',');

        const memStr = `${fmtPct(mem.used_pct)} ${fmtKb(mem.total_kb)}`;
        const swapStr = mem.swap_total_kb > 0 ? fmtPct(mem.swap_used_pct) : '-';
        const diskStr = `${fmtPct(disk.used_pct)} ${disk.total_mb ? Math.round(disk.total_mb / 1024) + 'G' : ''}`;
        const loadStr = s.load ? s.load['1min'].toFixed(2) : '-';
        const cpuStr = cpu.throttled ? `${C.yellow}${fmtTemp(s.cpu.temp_c)}!${C.reset}` : fmtTemp(s.cpu.temp_c);
        const gwStr = gw.reachable != null ? (gw.reachable ? `${gw.rtt_ms != null ? gw.rtt_ms.toFixed(0) + 'ms' : 'ok'}` : `${C.red}DOWN${C.reset}`) : '-';

        console.log(
            [
                pad(hostname, cols[0][1]),
                pad(ago(s.uptime_secs), cols[1][1]),
                pad(cpuStr, cols[2][1]),
                rpad(loadStr, cols[3][1]),
                pad(memStr, cols[4][1]),
                rpad(swapStr, cols[5][1]),
                pad(diskStr, cols[6][1]),
                pad(netStr, cols[7][1]),
                pad(indicator(mq.connected), cols[8][1]),
                pad(indicator(ts.synchronized), cols[9][1]),
                pad(gwStr, cols[10][1]),
                pad(resolve.ok != null ? indicator(resolve.ok) : '-', cols[11][1]),
            ].join('  ')
        );
    }
}

function showSystemDetailed(hosts) {
    for (const [hostname, d] of hosts) {
        const s = d.system || {};
        const mem = s.memory || {};
        const cpu = s.cpu || {};
        const disk = s.disk || {};
        const gw = s.gateway || {};
        const resolve = s.resolve || {};
        const mq = s.mqtt || {};
        const ts = s.timesync || {};

        console.log(`${C.bold}${C.cyan}═══ ${hostname} ═══${C.reset}`);
        console.log(`  Timestamp:    ${s.timestamp || '-'}`);
        console.log(`  Uptime:       ${s.uptime || '-'} (${s.uptime_secs || 0}s)`);

        // CPU
        console.log(`  CPU temp:     ${fmtTemp(s.cpu.temp_c)}`);
        if (cpu.cur_khz != null)
            console.log(
                `  CPU freq:     ${fmtFreq(cpu.cur_khz)} / ${fmtFreq(cpu.max_khz)} (${cpu.governor || '?'})${cpu.throttled ? ` ${C.yellow}THROTTLED${C.reset}` : ''}`
            );
        if (cpu.rpi_undervoltage) console.log(`  ${C.red}⚠ RPi undervoltage detected${C.reset}`);
        if (cpu.rpi_throttled_occurred) console.log(`  ${C.yellow}⚠ RPi throttling has occurred${C.reset}`);

        // Load
        if (s.load) console.log(`  Load:         ${s.load['1min']} / ${s.load['5min']} / ${s.load['15min']}`);

        // Memory
        console.log(`  Memory:       ${fmtKb(mem.total_kb)} total, ${fmtKb(mem.available_kb)} avail, ${fmtPct(mem.used_pct)} used`);
        if (mem.swap_total_kb > 0)
            console.log(`  Swap:         ${fmtKb(mem.swap_total_kb)} total, ${fmtKb(mem.swap_free_kb)} free, ${fmtPct(mem.swap_used_pct)} used`);

        // Disk
        console.log(
            `  Disk:         ${disk.total_mb || '?'}MB total, ${disk.used_mb || '?'}MB used, ${fmtPct(disk.used_pct)} used${disk.readonly ? ` ${C.red}READONLY${C.reset}` : ''}`
        );

        // Network
        for (const n of s.network || []) {
            const status = n.up ? `${C.green}UP${C.reset}` : `${C.red}DOWN${C.reset}`;
            console.log(`  Network ${n.name}: ${status}, ip=${n.ip || 'none'}, ${n.type}`);
            if (n.type === 'ethernet')
                console.log(`    Speed:      ${n.speed_mbps || '?'}Mbps ${n.duplex || ''}, MTU=${n.mtu || '?'}, carrier_changes=${n.carrier_changes ?? '?'}`);
            if (n.type === 'wifi') console.log(`    WiFi:       ${n.ssid || '?'}, ${n.signal_dbm || '?'}dBm, ${n.frequency || '?'}`);
            console.log(`    RX:         ${fmtBytes(n.rx_bytes)} (${n.rx_packets ?? '?'} pkts, ${n.rx_errors ?? 0} err, ${n.rx_dropped ?? 0} drop)`);
            console.log(`    TX:         ${fmtBytes(n.tx_bytes)} (${n.tx_packets ?? '?'} pkts, ${n.tx_errors ?? 0} err, ${n.tx_dropped ?? 0} drop)`);
        }

        // MQTT
        console.log(
            `  MQTT:         ${indicator(mq.connected)} connects=${mq.connects ?? '?'}, disconnects=${mq.disconnects ?? 0}, reconnects=${mq.reconnects ?? 0}`
        );
        console.log(`    Published:  ${mq.publishes ?? '?'} msgs, ${fmtBytes(mq.publish_bytes)}, errors=${mq.publish_errors ?? 0}`);
        if (mq.last_connect_time) console.log(`    Connected:  ${mq.last_connect_time} (${timeAge(mq.last_connect_time)})`);
        if (mq.last_publish_time) console.log(`    Last pub:   ${mq.last_publish_time} (${timeAge(mq.last_publish_time)})`);

        // Timesync
        const syncStr = ts.synchronized != null ? indicator(ts.synchronized) : '-';
        let tsDetail = `  Timesync:     ${syncStr}`;
        if (ts.source) tsDetail += `, source=${ts.source}`;
        if (ts.stratum != null) tsDetail += `, stratum=${ts.stratum}`;
        if (ts.offset_secs != null) tsDetail += `, offset=${(ts.offset_secs * 1000).toFixed(2)}ms`;
        console.log(tsDetail);

        // Gateway
        console.log(
            `  Gateway:      ${gw.ip || 'none'} via ${gw.interface || '?'}, ${gw.reachable ? `${C.green}reachable${C.reset} (${gw.rtt_ms != null ? gw.rtt_ms + 'ms' : ''})` : `${C.red}unreachable${C.reset}`}`
        );

        // DNS
        if (resolve.hostname) console.log(`  Resolve:      ${indicator(resolve.ok)} ${resolve.hostname} -> ${resolve.ip || 'FAILED'}`);

        // USB
        if (s.usb && s.usb.length > 0) {
            console.log(`  USB devices:  (${s.usb.length})`);
            for (const u of s.usb) {
                const desc = u.product || u.manufacturer || `${u.vendor_id}:${u.product_id}`;
                console.log(`    ${u.bus_id}: ${desc}${u.serial ? ` [${u.serial.substring(0, 12)}]` : ''}`);
            }
        }

        // Processes
        if (s.processes && s.processes.length > 0) {
            console.log(`  Processes:    (${s.processes.length})`);
            const procCols = [
                ['NAME', 20],
                ['PID', 7],
                ['RSS', 8],
                ['CPU', 10],
                ['UPTIME', 10],
                ['STATUS', 7],
            ];
            console.log(`    ${C.dim}${procCols.map(([n, w]) => pad(n, w)).join('  ')}${C.reset}`);
            for (const p of s.processes) {
                const status = p.running ? `${C.green}UP${C.reset}` : `${C.red}DOWN${C.reset}`;
                console.log(
                    '    ' +
                        [
                            pad(p.name, procCols[0][1]),
                            rpad(p.running ? String(p.pid) : '-', procCols[1][1]),
                            rpad(p.running ? fmtKb(p.rss_kb) : '-', procCols[2][1]),
                            rpad(p.cpu_secs != null ? p.cpu_secs.toFixed(1) + 's' : '-', procCols[3][1]),
                            pad(p.uptime_secs != null ? ago(p.uptime_secs) : '-', procCols[4][1]),
                            pad(status, procCols[5][1]),
                        ].join('  ')
                );
            }
        }

        console.log('');
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

function display() {
    const hosts = Object.entries(data).sort(([a], [b]) => a.localeCompare(b));
    if (hosts.length === 0) {
        console.error('No hosts found. Check MQTT connection and topic.');
        process.exit(1);
    }

    if (opts.mode === 'platform') {
        if (opts.detailed) showPlatformDetailed(hosts);
        else showPlatformSummary(hosts);
    } else {
        if (opts.detailed) showSystemDetailed(hosts);
        else showSystemSummary(hosts);
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

const client = mqtt.connect(opts.server, { connectTimeout: 5000 });
let timer = null;

client.on('connect', () => {
    client.subscribe(opts.topic, { qos: 0 });
    timer = setTimeout(() => {
        client.end(true);
        display();
        process.exit(0);
    }, opts.timeout);
});

client.on('message', (topic, payload) => {
    onMessage(topic, payload);
});

client.on('error', (err) => {
    console.error(`MQTT error: ${err.message}`);
    process.exit(1);
});

client.on('offline', () => {
    console.error(`Cannot connect to ${opts.server}`);
    process.exit(1);
});
