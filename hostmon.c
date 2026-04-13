// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

/*
 * hostmon — host system monitor for MQTT
 * Copyright(C) 2026 Matthew Gream (https://libiotdata.org)
 *
 * hostmon.c — publishes host system and network status to MQTT
 *
 * Monitors network interfaces (ethernet/wifi), system health (CPU temp,
 * memory, load, uptime), and publishes JSON payloads to MQTT with
 * retained messages for immediate delivery to new subscribers.
 *
 * Two publication intervals:
 *   - "platform" (slow): static/rarely changing info — hostname, OS version,
 *     kernel, architecture, boot time. Default 24 hours.
 *   - "system" (fast): dynamic info — network interface states, IPs,
 *     TX/RX counters, WiFi signal, CPU temp, memory, load. Default 60s.
 *
 * Network state changes (link up/down, IP change) trigger immediate
 * publication of platform data regardless of interval.
 *
 * Gracefully handles absent interfaces — works on devices with only
 * ethernet, only wifi, both, or neither.
 *
 * Uses libmosquitto for MQTT, cJSON for JSON construction.
 */

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <math.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/statvfs.h>
#include <sys/sysinfo.h>
#include <sys/utsname.h>

#include <cjson/cJSON.h>

volatile bool running = true;

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define MQTT_CONNECT_TIMEOUT 60
#define MQTT_PUBLISH_QOS     0
#define MQTT_PUBLISH_RETAIN  true
#include "mqtt_linux.h"

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define HOSTMON_VERSION                  "1.0.0"

#define CONFIG_FILE_DEFAULT              "hostmon.cfg"

#define MQTT_CLIENT_DEFAULT              "hostmon"
#define MQTT_SERVER_DEFAULT              "mqtt://localhost"
#define MQTT_TLS_DEFAULT                 false
#define MQTT_SYNCHRONOUS_DEFAULT         true
#define MQTT_TOPIC_PREFIX_DEFAULT        "hostmon"
#define MQTT_RECONNECT_DELAY_DEFAULT     5
#define MQTT_RECONNECT_DELAY_MAX_DEFAULT 60

#define INTERVAL_PLATFORM_DEFAULT        (24 * 60 * 60)
#define INTERVAL_SYSTEM_DEFAULT          60

typedef int serial_bits_t;
#define SERIAL_8N1 0
#include "config_linux.h"

// clang-format off
const struct option config_options[] = {
    {"help",                            no_argument,       0, 'h'},
    {"config",                          required_argument, 0, 0},
    {"mqtt-client",                     required_argument, 0, 0},
    {"mqtt-server",                     required_argument, 0, 0},
    {"mqtt-topic-prefix",               required_argument, 0, 0},
    {"mqtt-tls-insecure",               required_argument, 0, 0},
    {"mqtt-reconnect-delay",            required_argument, 0, 0},
    {"mqtt-reconnect-delay-max",        required_argument, 0, 0},
    {"interval-platform",               required_argument, 0, 0},
    {"interval-system",                 required_argument, 0, 0},
    {"check-processes",                 required_argument, 0, 0},
    {"check-timesync",                  required_argument, 0, 0},
    {"check-gateway",                   required_argument, 0, 0},
    {"check-dns",                       required_argument, 0, 0},
    {"debug",                           required_argument, 0, 0},
    {0, 0, 0, 0}
};

const config_option_help_t config_options_help[] = {
    {"help",                            "Display this help message and exit"},
    {"config",                          "Configuration file path (default: " CONFIG_FILE_DEFAULT ")"},
    {"mqtt-client",                     "MQTT client ID (default: " MQTT_CLIENT_DEFAULT ")"},
    {"mqtt-server",                     "MQTT server URL (default: " MQTT_SERVER_DEFAULT ")"},
    {"mqtt-topic-prefix",               "MQTT topic prefix (default: " MQTT_TOPIC_PREFIX_DEFAULT ")"},
    {"mqtt-tls-insecure",               "MQTT disable TLS verification (true/false)"},
    {"mqtt-reconnect-delay",            "MQTT reconnect delay in seconds"},
    {"mqtt-reconnect-delay-max",        "MQTT max reconnect delay in seconds"},
    {"interval-platform",               "Platform info publish interval in seconds (default: 86400)"},
    {"interval-system",                 "System info publish interval in seconds (default: 60)"},
    {"check-processes",                 "Check list of processes (comma-separated) (default: unspecified)"},
    {"check-timesync",                  "Check time synchronisation (default: true)"},
    {"check-gateway",                   "Check ping to network gateway (default: true)"},
    {"check-dns",                       "Check resolution of specified DNS host (default: unspecified)"},
    {"debug",                           "Enable debug output (true/false)"},
};
// clang-format on

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define MAX_INTERFACES     8
#define MAX_PROCESSES      16
#define INTERFACE_NAME_MAX 32
#define PROCESS_NAME_MAX   64
#define TOPIC_MAX          255

typedef struct {
    char name[INTERFACE_NAME_MAX];
    bool is_wifi;
    bool was_up;
    char prev_ip[INET_ADDRSTRLEN];
} iface_state_t;

typedef struct {
    char name[PROCESS_NAME_MAX];
    bool was_running;
} proc_watch_t;

typedef struct {
    const char *mqtt_topic_prefix;
    mqtt_config_t mqtt_config;
    time_t interval_platform;
    time_t interval_system;
    time_t interval_platform_last;
    time_t interval_system_last;
    bool debug;
    iface_state_t interfaces[MAX_INTERFACES];
    int interface_count;
    proc_watch_t processes[MAX_PROCESSES];
    int processes_count;
    bool check_timesync;
    bool check_gateway;
    const char *check_dns;
} hostmon_state_t;

static hostmon_state_t state;

static time_t last_publish_time = 0;

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static void string_memcpy(char *buf, size_t len, const char *str) {
    size_t str_len = strlen(str);
    if (str_len >= len)
        str_len = len - 1;
    memcpy(buf, str, str_len);
    buf[str_len] = '\0';
}

static const char *string_cleanup(char *str) {
    size_t str_len = strlen(str);
    while (str_len > 0 && (str[str_len - 1] == '\n' || str[str_len - 1] == '\r'))
        str[--str_len] = '\0';
    return str;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool read_file_line(const char *path, char *line_buf, size_t line_size) {
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    line_buf[0] = '\0';
    if (fgets(line_buf, (int)line_size, f))
        string_cleanup(line_buf);
    fclose(f);
    return line_buf[0] != '\0';
}

static bool read_file_uint64(const char *path, uint64_t *val) {
    char buf[64];
    if (!read_file_line(path, buf, sizeof(buf)))
        return false;
    char *end;
    *val = strtoull(buf, &end, 10);
    return *end == '\0' || *end == '\n';
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool ping_host(const char *host, double *rtt_ms) {
    if (rtt_ms)
        *rtt_ms = -1.0;
    char cmd[160];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W2 %s 2>/dev/null", host);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    char line[256];
    bool ok = false;
    while (fgets(line, (int)sizeof(line), f)) {
        // "rtt min/avg/max/mdev = 0.123/0.456/0.789/0.012 ms"
        const char *eq = strchr(line, '=');
        if (eq && (strstr(line, "rtt ") == line || strstr(line, "round-trip") == line)) {
            double mn, avg, mx, md;
            if (sscanf(eq + 1, " %lf/%lf/%lf/%lf", &mn, &avg, &mx, &md) >= 2) {
                if (rtt_ms)
                    *rtt_ms = avg;
                ok = true;
            }
        }
    }
    const int rc = pclose(f);
    return ok || rc == 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static char *get_timestamp_iso8601(void) {
    static char buf[32];
    const time_t now = time(NULL);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));
    return buf;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_iface_operstate(const char *name) {
    char path[PATH_MAX], buf[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/operstate", name);
    if (!read_file_line(path, buf, sizeof(buf)))
        return false;
    return strcmp(buf, "up") == 0;
}

static bool get_iface_ip(const char *name, char *ip_buf, size_t ip_size) {
    ip_buf[0] = '\0';
    struct ifaddrs *ifas, *ifa;
    if (getifaddrs(&ifas) != 0)
        return false;
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, name) != 0)
            continue;
        inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip_buf, (socklen_t)ip_size);
        break;
    }
    freeifaddrs(ifas);
    return ip_buf[0] != '\0';
}

static bool get_iface_mac(const char *name, char *mac_buf, size_t mac_size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/address", name);
    return read_file_line(path, mac_buf, mac_size);
}

static bool get_iface_speed(const char *name, int *speed) {
    char path[PATH_MAX], buf[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/speed", name);
    if (!read_file_line(path, buf, sizeof(buf)))
        return false;
    *speed = atoi(buf);
    return *speed > 0;
}

static bool get_iface_duplex(const char *name, char *buf, size_t size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/duplex", name);
    return read_file_line(path, buf, size);
}

static bool get_iface_counter(const char *name, const char *counter, uint64_t *val) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "/sys/class/net/%s/statistics/%s", name, counter);
    return read_file_uint64(path, val);
}

static bool get_iface_mtu(const char *name, int *mtu) {
    char path[PATH_MAX], buf[32];
    snprintf(path, sizeof(path), "/sys/class/net/%s/mtu", name);
    if (!read_file_line(path, buf, sizeof(buf)))
        return false;
    *mtu = atoi(buf);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_wifi_ssid(const char *name, char *ssid_buf, size_t ssid_size) {
    ssid_buf[0] = '\0';
    char cmd[128], buf[256];
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | awk '/ssid/{print $2}'", name);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    if (fgets(buf, (int)sizeof(buf), f))
        snprintf(ssid_buf, ssid_size, "%s", string_cleanup(buf));
    pclose(f);
    return ssid_buf[0] != '\0';
}

static bool get_wifi_signal(const char *name, int *signal_dbm) {
    FILE *f = fopen("/proc/net/wireless", "r");
    if (!f)
        return false;
    char line[256];
    if (!fgets(line, (int)sizeof(line), f) || !fgets(line, (int)sizeof(line), f)) {
        fclose(f);
        return false;
    }
    bool found = false;
    while (fgets(line, (int)sizeof(line), f)) {
        char iface[INTERFACE_NAME_MAX];
        int status;
        float link, level;
        if (sscanf(line, " %31[^:]: %d %f %f", iface, &status, &link, &level) >= 4)
            if (strcmp(iface, name) == 0) {
                *signal_dbm = (int)level;
                found = true;
                break;
            }
    }
    fclose(f);
    return found;
}

static bool get_wifi_frequency(const char *name, char *freq_buf, size_t freq_size) {
    freq_buf[0] = '\0';
    char cmd[128], buf[256];
    snprintf(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | awk '/channel/{print $2\"ch \"$5\" MHz\"}'", name);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    if (fgets(buf, (int)sizeof(buf), f))
        snprintf(freq_buf, freq_size, "%s", string_cleanup(buf));
    pclose(f);
    return freq_buf[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static int interfaces_discover(void) {
    state.interface_count = 0;
    DIR *d = opendir("/sys/class/net");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL && state.interface_count < MAX_INTERFACES) {
            if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
                continue;
            if (strcmp(ent->d_name, "lo") == 0)
                continue;
            iface_state_t *iface = &state.interfaces[state.interface_count];
            string_memcpy(iface->name, sizeof(iface->name), ent->d_name);
            char path[PATH_MAX];
            snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", ent->d_name);
            iface->is_wifi = (access(path, F_OK) == 0);
            iface->was_up = false;
            iface->prev_ip[0] = '\0';
            state.interface_count++;
            if (state.debug)
                printf("hostmon: discovered interface %s (%s)\n", iface->name, iface->is_wifi ? "wifi" : "ethernet");
        }
        closedir(d);
    }
    return state.interface_count;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool interfaces_check_state_changes(void) {
    bool changed = false;
    for (int i = 0; i < state.interface_count; i++) {
        iface_state_t *iface = &state.interfaces[i];
        const bool up = get_iface_operstate(iface->name);
        char ip[INET_ADDRSTRLEN];
        get_iface_ip(iface->name, ip, sizeof(ip));
        if (up != iface->was_up) {
            printf("hostmon: %s link %s -> %s\n", iface->name, iface->was_up ? "up" : "down", up ? "up" : "down");
            iface->was_up = up;
            changed = true;
        }
        if (strcmp(ip, iface->prev_ip) != 0) {
            if (iface->prev_ip[0] != '\0' || ip[0] != '\0') {
                printf("hostmon: %s ip %s -> %s\n", iface->name, iface->prev_ip[0] ? iface->prev_ip : "(none)", ip[0] ? ip : "(none)");
                changed = true;
            }
            snprintf(iface->prev_ip, sizeof(iface->prev_ip), "%s", ip);
        }
    }
    return changed;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void interfaces_init(void) {
    for (int i = 0; i < state.interface_count; i++) {
        iface_state_t *iface = &state.interfaces[i];
        iface->was_up = get_iface_operstate(iface->name);
        get_iface_ip(iface->name, iface->prev_ip, sizeof(iface->prev_ip));
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *interfaces_build_json(const iface_state_t *iface) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", iface->name);
    cJSON_AddStringToObject(obj, "type", iface->is_wifi ? "wifi" : "ethernet");

    const bool up = get_iface_operstate(iface->name);
    cJSON_AddBoolToObject(obj, "up", up);

    char ip[INET_ADDRSTRLEN];
    if (get_iface_ip(iface->name, ip, sizeof(ip)))
        cJSON_AddStringToObject(obj, "ip", ip);

    int mtu;
    if (get_iface_mtu(iface->name, &mtu))
        cJSON_AddNumberToObject(obj, "mtu", mtu);

    char path[PATH_MAX];
    uint64_t carrier_changes;
    snprintf(path, sizeof(path), "/sys/class/net/%s/carrier_changes", iface->name);
    if (read_file_uint64(path, &carrier_changes))
        cJSON_AddNumberToObject(obj, "carrier_changes", (double)carrier_changes);

    if (!iface->is_wifi) {
        int speed_mbps;
        if (get_iface_speed(iface->name, &speed_mbps))
            cJSON_AddNumberToObject(obj, "speed_mbps", speed_mbps);
        char duplex[16];
        if (get_iface_duplex(iface->name, duplex, sizeof(duplex)))
            cJSON_AddStringToObject(obj, "duplex", duplex);
    } else {
        char ssid[64];
        if (get_wifi_ssid(iface->name, ssid, sizeof(ssid)))
            cJSON_AddStringToObject(obj, "ssid", ssid);
        int signal_dbm;
        if (get_wifi_signal(iface->name, &signal_dbm))
            cJSON_AddNumberToObject(obj, "signal_dbm", signal_dbm);
        char frequency[32];
        if (get_wifi_frequency(iface->name, frequency, sizeof(frequency)))
            cJSON_AddStringToObject(obj, "frequency", frequency);
    }

    // counters
    uint64_t val;
    if (get_iface_counter(iface->name, "rx_bytes", &val))
        cJSON_AddNumberToObject(obj, "rx_bytes", (double)val);
    if (get_iface_counter(iface->name, "tx_bytes", &val))
        cJSON_AddNumberToObject(obj, "tx_bytes", (double)val);
    if (get_iface_counter(iface->name, "rx_packets", &val))
        cJSON_AddNumberToObject(obj, "rx_packets", (double)val);
    if (get_iface_counter(iface->name, "tx_packets", &val))
        cJSON_AddNumberToObject(obj, "tx_packets", (double)val);
    if (get_iface_counter(iface->name, "rx_errors", &val))
        cJSON_AddNumberToObject(obj, "rx_errors", (double)val);
    if (get_iface_counter(iface->name, "tx_errors", &val))
        cJSON_AddNumberToObject(obj, "tx_errors", (double)val);
    if (get_iface_counter(iface->name, "rx_dropped", &val))
        cJSON_AddNumberToObject(obj, "rx_dropped", (double)val);
    if (get_iface_counter(iface->name, "tx_dropped", &val))
        cJSON_AddNumberToObject(obj, "tx_dropped", (double)val);

    return obj;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *timesync_build_json(void) {
    cJSON *timesync = cJSON_CreateObject();

    // try timedatectl (systemd-timesyncd)
    FILE *f = popen("timedatectl show --property=NTPSynchronized --value 2>/dev/null", "r");
    if (f) {
        char buf[32];
        if (fgets(buf, (int)sizeof(buf), f))
            cJSON_AddBoolToObject(timesync, "synchronized", strcmp(string_cleanup(buf), "yes") == 0);
        pclose(f);
    }

    // try chronyc for offset
    f = popen("chronyc tracking 2>/dev/null", "r");
    if (f) {
        char line[256];
        bool found_source = false;
        while (fgets(line, (int)sizeof(line), f)) {
            if (!found_source && strncmp(line, "Reference ID", 12) == 0) {
                const char *paren = strchr(line, '(');
                if (paren) {
                    char *end = strchr(paren + 1, ')');
                    if (end) {
                        *end = '\0';
                        cJSON_AddStringToObject(timesync, "source", paren + 1);
                        found_source = true;
                    }
                }
            }
            if (strncmp(line, "Last offset", 11) == 0) {
                const char *colon = strchr(line, ':');
                if (colon) {
                    double offset_secs;
                    if (sscanf(colon + 1, " %lf", &offset_secs) == 1)
                        cJSON_AddNumberToObject(timesync, "offset_secs", offset_secs);
                }
            }
            if (strncmp(line, "Stratum", 7) == 0) {
                const char *colon = strchr(line, ':');
                if (colon)
                    cJSON_AddNumberToObject(timesync, "stratum", atoi(colon + 1));
            }
        }
        pclose(f);
    }

    return timesync;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool is_process_running(const char *name, int *pid_out, unsigned long *rss_kb_out) {
    *pid_out = 0;
    *rss_kb_out = 0;
    DIR *d = opendir("/proc");
    if (!d)
        return false;
    struct dirent *ent;
    bool found = false;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/proc/%s/comm", ent->d_name);
        char comm[PROCESS_NAME_MAX];
        if (!read_file_line(path, comm, sizeof(comm)))
            continue;
        if (strcmp(comm, name) == 0) {
            *pid_out = atoi(ent->d_name);
            // read RSS from /proc/PID/statm (second field, in pages)
            snprintf(path, sizeof(path), "/proc/%s/statm", ent->d_name);
            FILE *f = fopen(path, "r");
            if (f) {
                unsigned long size_pages, rss_pages;
                if (fscanf(f, "%lu %lu", &size_pages, &rss_pages) == 2) {
                    const long page_size = sysconf(_SC_PAGESIZE);
                    if (page_size > 0)
                        *rss_kb_out = rss_pages * (unsigned long)page_size / 1024;
                }
                fclose(f);
            }
            found = true;
            break;
        }
    }
    closedir(d);
    return found;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void processes_parse(const char *csv) {
    if (!csv || !*csv)
        return;
    char buf[1024];
    string_memcpy(buf, sizeof(buf), csv);
    char *saveptr = NULL, *tok = strtok_r(buf, ",", &saveptr);
    while (tok && state.processes_count < MAX_PROCESSES) {
        while (*tok == ' ')
            tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ')
            *end-- = '\0';
        if (*tok) {
            proc_watch_t *pw = &state.processes[state.processes_count];
            string_memcpy(pw->name, sizeof(pw->name), tok);
            pw->was_running = false;
            state.processes_count++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool processes_check_state_changes(void) {
    bool changed = false;
    for (int i = 0; i < state.processes_count; i++) {
        int pid;
        unsigned long rss_kb;
        const bool running_now = is_process_running(state.processes[i].name, &pid, &rss_kb);
        if (running_now != state.processes[i].was_running) {
            printf("hostmon: process '%s' %s -> %s\n", state.processes[i].name, state.processes[i].was_running ? "running" : "stopped", running_now ? "running" : "stopped");
            state.processes[i].was_running = running_now;
            changed = true;
        }
    }
    return changed;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void processes_init(void) {
    for (int i = 0; i < state.processes_count; i++) {
        int pid;
        unsigned long rss_kb;
        state.processes[i].was_running = is_process_running(state.processes[i].name, &pid, &rss_kb);
        printf("hostmon: watching process '%s' (%s)\n", state.processes[i].name, state.processes[i].was_running ? "running" : "not found");
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *processes_build_json(void) {
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < state.processes_count; i++) {
        cJSON *pobj = cJSON_CreateObject();
        cJSON_AddStringToObject(pobj, "name", state.processes[i].name);
        int pid;
        unsigned long rss_kb;
        const bool running_now = is_process_running(state.processes[i].name, &pid, &rss_kb);
        cJSON_AddBoolToObject(pobj, "running", running_now);
        if (running_now) {
            cJSON_AddNumberToObject(pobj, "pid", pid);
            cJSON_AddNumberToObject(pobj, "rss_kb", (double)rss_kb);
            // uptime of the process
            char path[PATH_MAX], buf[1024];
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);
            FILE *f = fopen(path, "r");
            if (f) {
                // field 22 is starttime in clock ticks
                if (fgets(buf, (int)sizeof(buf), f)) {
                    // skip past the comm field (which may contain spaces/parens)
                    const char *cp = strrchr(buf, ')');
                    if (cp) {
                        unsigned long long starttime = 0;
                        // fields after ')' are: state, ppid, pgrp, session, tty_nr, tpgid,
                        //   flags, minflt, cminflt, majflt, cmajflt, utime, stime, cutime,
                        //   cstime, priority, nice, num_threads, itrealvalue, starttime
                        const int n = sscanf(cp + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u %*u %*d %*d %*d %*d %*d %*d %llu", &starttime);
                        if (n == 1) {
                            const long hz = sysconf(_SC_CLK_TCK);
                            if (hz > 0) {
                                struct sysinfo si;
                                if (sysinfo(&si) == 0) {
                                    const long proc_uptime = si.uptime - (long)(starttime / (unsigned long long)hz);
                                    if (proc_uptime >= 0)
                                        cJSON_AddNumberToObject(pobj, "uptime_secs", (double)proc_uptime);
                                }
                            }
                        }
                    }
                }
                fclose(f);
            }
            // cpu time (utime + stime)
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);
            f = fopen(path, "r");
            if (f) {
                if (fgets(buf, (int)sizeof(buf), f)) {
                    const char *cp = strrchr(buf, ')');
                    if (cp) {
                        unsigned long utime = 0, stime = 0;
                        sscanf(cp + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &utime, &stime);
                        const long hz = sysconf(_SC_CLK_TCK);
                        if (hz > 0)
                            cJSON_AddNumberToObject(pobj, "cpu_secs", (double)(utime + stime) / (double)hz);
                    }
                }
                fclose(f);
            }
        }
        cJSON_AddItemToArray(arr, pobj);
    }
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_cpu_temp(double *temp) {
    // try thermal zones
    for (int i = 0; i < 10; i++) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", i);
        uint64_t val;
        if (read_file_uint64(path, &val)) {
            *temp = (double)val / 1000.0;
            return true;
        }
    }
    return false;
}

static bool get_memory_info(uint64_t *total_kb, uint64_t *available_kb, uint64_t *free_kb, uint64_t *swap_total_kb, uint64_t *swap_free_kb) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return false;
    char line[128];
    int found = 0;
    *total_kb = *available_kb = *free_kb = *swap_total_kb = *swap_free_kb = 0;
    while (fgets(line, (int)sizeof(line), f) && found < 5) {
        unsigned long val;
        if (sscanf(line, "MemTotal: %lu", &val) == 1) {
            *total_kb = (uint64_t)val;
            found++;
        } else if (sscanf(line, "MemAvailable: %lu", &val) == 1) {
            *available_kb = (uint64_t)val;
            found++;
        } else if (sscanf(line, "MemFree: %lu", &val) == 1) {
            *free_kb = (uint64_t)val;
            found++;
        } else if (sscanf(line, "SwapTotal: %lu", &val) == 1) {
            *swap_total_kb = (uint64_t)val;
            found++;
        } else if (sscanf(line, "SwapFree: %lu", &val) == 1) {
            *swap_free_kb = (uint64_t)val;
            found++;
        }
    }
    fclose(f);
    return *total_kb > 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_cpu_freq(uint64_t *cur_khz, uint64_t *max_khz) {
    *cur_khz = *max_khz = 0;
    read_file_uint64("/sys/devices/system/cpu/cpu0/cpufreq/scaling_cur_freq", cur_khz);
    read_file_uint64("/sys/devices/system/cpu/cpu0/cpufreq/scaling_max_freq", max_khz);
    return *cur_khz > 0 || *max_khz > 0;
}

static bool get_rpi_throttled(uint64_t *flags) {
    return read_file_uint64("/sys/devices/platform/soc/soc:firmware/get_throttled", flags);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *mmc_health_build_json(void) {
    cJSON *arr = NULL;
    DIR *d = opendir("/sys/block");
    if (!d)
        return NULL;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strncmp(ent->d_name, "mmcblk", 6) != 0)
            continue;
        // only root devices (e.g. mmcblk0), skip partitions (mmcblk0p1)
        if (strchr(ent->d_name, 'p') != NULL)
            continue;
        char path[PATH_MAX], buf[128];
        snprintf(path, sizeof(path), "/sys/block/%s/device/life_time", ent->d_name);
        if (!read_file_line(path, buf, sizeof(buf)))
            continue;
        unsigned int type_a = 0, type_b = 0;
        if (sscanf(buf, "%x %x", &type_a, &type_b) < 1)
            continue;
        if (!arr)
            arr = cJSON_CreateArray();
        cJSON *dev = cJSON_CreateObject();
        cJSON_AddStringToObject(dev, "name", ent->d_name);
        cJSON_AddNumberToObject(dev, "life_time_a", (double)type_a);
        cJSON_AddNumberToObject(dev, "life_time_b", (double)type_b);
        // map: 0x01=0-10%, 0x02=10-20%, ... 0x0B=90-100%
        if (type_a >= 1 && type_a <= 0x0B)
            cJSON_AddNumberToObject(dev, "used_pct_max_a", (double)(type_a * 10));
        if (type_b >= 1 && type_b <= 0x0B)
            cJSON_AddNumberToObject(dev, "used_pct_max_b", (double)(type_b * 10));
        snprintf(path, sizeof(path), "/sys/block/%s/device/pre_eol_info", ent->d_name);
        if (read_file_line(path, buf, sizeof(buf))) {
            unsigned int eol = 0;
            if (sscanf(buf, "%x", &eol) == 1)
                cJSON_AddNumberToObject(dev, "pre_eol_info", (double)eol);
        }
        cJSON_AddItemToArray(arr, dev);
    }
    closedir(d);
    return arr;
}

static bool get_load_averages(double *load1, double *load5, double *load15) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f)
        return false;
    const bool ok = (fscanf(f, "%lf %lf %lf", load1, load5, load15) == 3);
    fclose(f);
    return ok;
}

static bool get_disk_usage(const char *path, uint64_t *total_mb, uint64_t *used_mb, uint64_t *avail_mb) {
    struct statvfs st;
    if (statvfs(path, &st) != 0)
        return false;
    *total_mb = (uint64_t)st.f_blocks * st.f_frsize / (1024 * 1024);
    *avail_mb = (uint64_t)st.f_bavail * st.f_frsize / (1024 * 1024);
    *used_mb = *total_mb - (uint64_t)st.f_bfree * st.f_frsize / (1024 * 1024);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool is_filesystem_readonly(const char *mountpoint) {
    struct statvfs st;
    if (statvfs(mountpoint, &st) != 0)
        return false;
    return (st.f_flag & ST_RDONLY) != 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool check_dns_resolution(const char *hostname, char *result_ip, size_t result_size) {
    result_ip[0] = '\0';
    if (!hostname || !*hostname)
        return false;
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return false;
    if (res && res->ai_addr)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)res->ai_addr)->sin_addr, result_ip, (socklen_t)result_size);
    freeaddrinfo(res);
    return result_ip[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_default_gateway(char *gw_buf, size_t gw_size, char *iface_buf, size_t iface_size) {
    gw_buf[0] = '\0';
    if (iface_buf && iface_size > 0)
        iface_buf[0] = '\0';
    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return false;
    char line[256];
    if (!fgets(line, (int)sizeof(line), f)) {
        fclose(f);
        return false;
    }
    while (fgets(line, (int)sizeof(line), f)) {
        char iface[32];
        unsigned long dest, gateway;
        if (sscanf(line, "%31s %lx %lx", iface, &dest, &gateway) == 3)
            if (dest == 0 && gateway != 0) {
                const struct in_addr addr = { .s_addr = (in_addr_t)gateway };
                inet_ntop(AF_INET, &addr, gw_buf, (socklen_t)gw_size);
                if (iface_buf && iface_size > 0)
                    string_memcpy(iface_buf, iface_size, iface);
                break;
            }
    }
    fclose(f);
    return gw_buf[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *usbdevs_build_json(void) {
    cJSON *arr = cJSON_CreateArray();
    DIR *d = opendir("/sys/bus/usb/devices");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            if (ent->d_name[0] == '.')
                continue;
            // skip interface entries (contain ':')
            if (strchr(ent->d_name, ':') != NULL)
                continue;
            // skip root hubs (usb1, usb2, etc.)
            if (strncmp(ent->d_name, "usb", 3) == 0)
                continue;
            char path[PATH_MAX], buf[128];
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", ent->d_name);
            if (!read_file_line(path, buf, sizeof(buf)))
                continue;
            cJSON *dev = cJSON_CreateObject();
            cJSON_AddStringToObject(dev, "bus_id", ent->d_name);
            cJSON_AddStringToObject(dev, "vendor_id", buf);
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", ent->d_name);
            if (read_file_line(path, buf, sizeof(buf)))
                cJSON_AddStringToObject(dev, "product_id", buf);
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/manufacturer", ent->d_name);
            if (read_file_line(path, buf, sizeof(buf)))
                cJSON_AddStringToObject(dev, "manufacturer", buf);
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/product", ent->d_name);
            if (read_file_line(path, buf, sizeof(buf)))
                cJSON_AddStringToObject(dev, "product", buf);
            snprintf(path, sizeof(path), "/sys/bus/usb/devices/%s/serial", ent->d_name);
            if (read_file_line(path, buf, sizeof(buf)))
                cJSON_AddStringToObject(dev, "serial", buf);
            cJSON_AddItemToArray(arr, dev);
        }
        closedir(d);
    }
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *build_system_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", get_timestamp_iso8601());
    cJSON_AddStringToObject(root, "type", "system");

    // show uptime
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        cJSON_AddNumberToObject(root, "uptime_secs", (double)si.uptime);
        char uptime[64];
        snprintf(uptime, sizeof(uptime), "%dd %dh %dm", (int)(si.uptime / 86400), (int)((si.uptime % 86400) / 3600), (int)((si.uptime % 3600) / 60));
        cJSON_AddStringToObject(root, "uptime", uptime);
    }

    // show temp
    double cpu_temp_c;
    if (get_cpu_temp(&cpu_temp_c))
        cJSON_AddNumberToObject(root, "cpu_temp_c", round(cpu_temp_c * 10.0) / 10.0);

    // show load
    double load_1min, load_5min, load_15min;
    if (get_load_averages(&load_1min, &load_5min, &load_15min)) {
        cJSON *load = cJSON_AddObjectToObject(root, "load");
        cJSON_AddNumberToObject(load, "1min", load_1min);
        cJSON_AddNumberToObject(load, "5min", load_5min);
        cJSON_AddNumberToObject(load, "15min", load_15min);
    }

    // show memory
    uint64_t mem_total_kb, mem_available_kb, mem_free_kb, swap_total_kb, swap_free_kb;
    if (get_memory_info(&mem_total_kb, &mem_available_kb, &mem_free_kb, &swap_total_kb, &swap_free_kb)) {
        cJSON *mem = cJSON_AddObjectToObject(root, "memory");
        cJSON_AddNumberToObject(mem, "total_kb", (double)mem_total_kb);
        cJSON_AddNumberToObject(mem, "available_kb", (double)mem_available_kb);
        cJSON_AddNumberToObject(mem, "free_kb", (double)mem_free_kb);
        if (mem_total_kb > 0)
            cJSON_AddNumberToObject(mem, "used_pct", round(1000.0 * (double)(mem_total_kb - mem_available_kb) / (double)mem_total_kb) / 10.0);
        cJSON_AddNumberToObject(mem, "swap_total_kb", (double)swap_total_kb);
        cJSON_AddNumberToObject(mem, "swap_free_kb", (double)swap_free_kb);
        if (swap_total_kb > 0)
            cJSON_AddNumberToObject(mem, "swap_used_pct", round(1000.0 * (double)(swap_total_kb - swap_free_kb) / (double)swap_total_kb) / 10.0);
    }

    // show cpu frequency / throttling
    uint64_t cpu_cur_khz, cpu_max_khz;
    if (get_cpu_freq(&cpu_cur_khz, &cpu_max_khz)) {
        cJSON *cpu = cJSON_AddObjectToObject(root, "cpu");
        if (cpu_cur_khz > 0)
            cJSON_AddNumberToObject(cpu, "cur_khz", (double)cpu_cur_khz);
        if (cpu_max_khz > 0)
            cJSON_AddNumberToObject(cpu, "max_khz", (double)cpu_max_khz);
        if (cpu_cur_khz > 0 && cpu_max_khz > 0)
            cJSON_AddBoolToObject(cpu, "throttled", cpu_cur_khz < cpu_max_khz);
        uint64_t rpi_flags;
        if (get_rpi_throttled(&rpi_flags)) {
            // bit 0: under-voltage now, 1: freq capped now, 2: throttled now, 3: soft temp limit now
            // bit 16: under-voltage occurred, 17: freq capped occurred, 18: throttled occurred, 19: soft temp limit occurred
            cJSON_AddNumberToObject(cpu, "rpi_throttled_flags", (double)rpi_flags);
            cJSON_AddBoolToObject(cpu, "rpi_undervoltage", (rpi_flags & 0x1) != 0);
            cJSON_AddBoolToObject(cpu, "rpi_freq_capped", (rpi_flags & 0x2) != 0);
            cJSON_AddBoolToObject(cpu, "rpi_throttled_now", (rpi_flags & 0x4) != 0);
            cJSON_AddBoolToObject(cpu, "rpi_soft_temp_limit", (rpi_flags & 0x8) != 0);
            cJSON_AddBoolToObject(cpu, "rpi_undervoltage_occurred", (rpi_flags & 0x10000) != 0);
            cJSON_AddBoolToObject(cpu, "rpi_throttled_occurred", (rpi_flags & 0x40000) != 0);
        }
    }

    // show network interfaces
    cJSON *interfaces = cJSON_AddArrayToObject(root, "network");
    for (int i = 0; i < state.interface_count; i++)
        cJSON_AddItemToArray(interfaces, interfaces_build_json(&state.interfaces[i]));

    // show mqtt connection status
    cJSON *mqtt = cJSON_AddObjectToObject(root, "mqtt");
    cJSON_AddBoolToObject(mqtt, "connected", mqtt_is_connected());
    cJSON_AddNumberToObject(mqtt, "connects", (double)mqtt_stat_connects);
    cJSON_AddNumberToObject(mqtt, "disconnects", (double)mqtt_stat_disconnects);
    cJSON_AddNumberToObject(mqtt, "reconnects", (double)mqtt_stat_reconnects);
    cJSON_AddNumberToObject(mqtt, "publishes", (double)mqtt_stat_publishes);
    cJSON_AddNumberToObject(mqtt, "publish_bytes", (double)mqtt_stat_publish_bytes);
    cJSON_AddNumberToObject(mqtt, "publish_errors", (double)mqtt_stat_publish_errors);
    if (mqtt_stat_last_connect_time > 0) {
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&mqtt_stat_last_connect_time));
        cJSON_AddStringToObject(mqtt, "last_connect_time", ts);
    }
    if (last_publish_time > 0) {
        char ts[32];
        strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&last_publish_time));
        cJSON_AddStringToObject(mqtt, "last_publish_time", ts);
    }

    // show disk usage (root filesystem)
    uint64_t disk_total_mb, disk_used_mb, disk_avail_mb;
    if (get_disk_usage("/", &disk_total_mb, &disk_used_mb, &disk_avail_mb)) {
        cJSON *disk = cJSON_AddObjectToObject(root, "disk");
        cJSON_AddNumberToObject(disk, "total_mb", (double)disk_total_mb);
        cJSON_AddNumberToObject(disk, "used_mb", (double)disk_used_mb);
        cJSON_AddNumberToObject(disk, "avail_mb", (double)disk_avail_mb);
        if (disk_total_mb > 0)
            cJSON_AddNumberToObject(disk, "used_pct", round(1000.0 * (double)disk_used_mb / (double)disk_total_mb) / 10.0);
        cJSON_AddBoolToObject(disk, "readonly", is_filesystem_readonly("/"));
    }

    // show eMMC/SD health
    cJSON *mmc = mmc_health_build_json();
    if (mmc)
        cJSON_AddItemToObject(root, "mmc", mmc);

    // show USB devices
    cJSON *usb = usbdevs_build_json();
    if (usb)
        cJSON_AddItemToObject(root, "usb", usb);

    // check processes
    if (state.processes_count > 0) {
        cJSON *processes = processes_build_json();
        if (processes)
            cJSON_AddItemToObject(root, "processes", processes);
    }

    // check time synchronisation
    if (state.check_timesync) {
        cJSON *timesync = timesync_build_json();
        if (timesync)
            cJSON_AddItemToObject(root, "timesync", timesync);
    }

    // check gateway reachability
    if (state.check_gateway) {
        cJSON *gateway = cJSON_AddObjectToObject(root, "gateway");
        char gw_ip[INET_ADDRSTRLEN], gw_iface[INTERFACE_NAME_MAX];
        if (get_default_gateway(gw_ip, sizeof(gw_ip), gw_iface, sizeof(gw_iface))) {
            cJSON_AddStringToObject(gateway, "ip", gw_ip);
            if (gw_iface[0])
                cJSON_AddStringToObject(gateway, "interface", gw_iface);
            double rtt_ms = -1.0;
            const bool reachable = ping_host(gw_ip, &rtt_ms);
            cJSON_AddBoolToObject(gateway, "reachable", reachable);
            if (reachable && rtt_ms >= 0.0)
                cJSON_AddNumberToObject(gateway, "rtt_ms", round(rtt_ms * 100.0) / 100.0);
        } else {
            cJSON_AddStringToObject(gateway, "ip", "none");
            cJSON_AddBoolToObject(gateway, "reachable", false);
        }
    }

    // check DNS resolution
    if (state.check_dns && *state.check_dns) {
        cJSON *dns = cJSON_AddObjectToObject(root, "dns");
        cJSON_AddStringToObject(dns, "check_host", state.check_dns);
        char resolved_ip[INET_ADDRSTRLEN];
        const bool resolved = check_dns_resolution(state.check_dns, resolved_ip, sizeof(resolved_ip));
        cJSON_AddBoolToObject(dns, "ok", resolved);
        if (resolved)
            cJSON_AddStringToObject(dns, "resolved_ip", resolved_ip);
    }

    return root;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *build_platform_json(void) {
    struct utsname uts;
    if (uname(&uts) != 0)
        return NULL;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", get_timestamp_iso8601());
    cJSON_AddStringToObject(root, "type", "platform");
    cJSON_AddStringToObject(root, "hostmon_version", HOSTMON_VERSION);

    cJSON_AddStringToObject(root, "hostname", uts.nodename);
    cJSON_AddStringToObject(root, "kernel", uts.release);
    cJSON_AddStringToObject(root, "kernel_version", uts.version);
    cJSON_AddStringToObject(root, "arch", uts.machine);
    cJSON_AddStringToObject(root, "os", uts.sysname);

    // os-release
    char buf[256];
    if (read_file_line("/etc/hostname", buf, sizeof(buf)))
        cJSON_AddStringToObject(root, "hostname_file", buf);
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, (int)sizeof(line), f))
            if (strncmp(line, "PRETTY_NAME=", 12) == 0) {
                char *val = line + 12;
                size_t len = strlen(val);
                while (len > 0 && (val[len - 1] == '\n' || val[len - 1] == '"'))
                    val[--len] = '\0';
                if (*val == '"')
                    val++;
                cJSON_AddStringToObject(root, "os_pretty", val);
                break;
            }
        fclose(f);
    }

    // boot time
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        char boot_time[32];
        const time_t boot_timet = time(NULL) - si.uptime;
        strftime(boot_time, sizeof(boot_time), "%Y-%m-%dT%H:%M:%SZ", gmtime(&boot_timet));
        cJSON_AddStringToObject(root, "boot_time", boot_time);
    }

    // list discovered interfaces
    cJSON *interfaces = cJSON_AddArrayToObject(root, "interfaces");
    for (int i = 0; i < state.interface_count; i++) {
        cJSON *interface = cJSON_CreateObject();
        cJSON_AddStringToObject(interface, "name", state.interfaces[i].name);
        cJSON_AddStringToObject(interface, "type", state.interfaces[i].is_wifi ? "wifi" : "ethernet");
        char mac[24];
        if (get_iface_mac(state.interfaces[i].name, mac, sizeof(mac)))
            cJSON_AddStringToObject(interface, "mac", mac);
        cJSON_AddItemToArray(interfaces, interface);
    }

    return root;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool publish_json(const char *subtopic, cJSON *json) {
    if (!json || !mqtt_is_connected())
        return false;
    char *str = cJSON_PrintUnformatted(json);
    if (!str) {
        cJSON_Delete(json);
        return false;
    }
    char topic[TOPIC_MAX], hostname[64];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        snprintf(hostname, sizeof(hostname), "unknown");
    snprintf(topic, sizeof(topic), "%s/%s/%s", state.mqtt_topic_prefix, hostname, subtopic);
    const bool ok = mqtt_send(topic, str, (int)strlen(str));
    if (ok)
        last_publish_time = time(NULL);
    if (state.debug)
        printf("hostmon: publish %s (%d bytes) -> %s\n", subtopic, (int)strlen(str), ok ? "ok" : "FAILED");
    free(str);
    cJSON_Delete(json);
    return ok;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static time_t intervalable(const time_t interval, time_t *last, bool forced) {
    time_t now = time(NULL);
    if (*last == 0) {
        *last = now;
        return 0;
    }
    if ((now - *last) > interval || forced) {
        const time_t diff = now - *last;
        *last = now;
        return diff ? diff : (forced ? 1 : 0);
    }
    return 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void hostmon_run(void) {

    printf("hostmon: running (platform=%lds, system=%lds, interfaces=%d, procs=%d, dns=%s, topic=%s)\n", (long)state.interval_platform, (long)state.interval_system, state.interface_count, state.processes_count,
           state.check_dns ? state.check_dns : "none", state.mqtt_topic_prefix);

    processes_init();
    interfaces_init();

    publish_json("platform", build_platform_json());
    state.interval_platform_last = time(NULL);
    publish_json("system", build_system_json());
    state.interval_system_last = time(NULL);

    while (running) {

        bool forced = false;
        if (interfaces_check_state_changes()) {
            printf("hostmon: network state changes, publishing immediately\n");
            forced = true;
        }
        if (processes_check_state_changes()) {
            printf("hostmon: process state changes, publishing immediately\n");
            forced = true;
        }

        if (intervalable(state.interval_platform, &state.interval_platform_last, false))
            publish_json("platform", build_platform_json());

        if (intervalable(state.interval_system, &state.interval_system_last, forced))
            publish_json("system", build_system_json());

        if (state.mqtt_config.use_synchronous)
            mqtt_loop(1000);
        else
            usleep(1000000); /* 1 second */
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static void mqtt_config_populate(mqtt_config_t *cfg) {
    memset(cfg, 0, sizeof(*cfg));
    cfg->client = config_get_string("mqtt-client", MQTT_CLIENT_DEFAULT);
    cfg->server = config_get_string("mqtt-server", MQTT_SERVER_DEFAULT);
    cfg->tls_insecure = config_get_bool("mqtt-tls-insecure", MQTT_TLS_DEFAULT);
    cfg->use_synchronous = MQTT_SYNCHRONOUS_DEFAULT;
    cfg->reconnect_delay = (unsigned int)config_get_integer("mqtt-reconnect-delay", MQTT_RECONNECT_DELAY_DEFAULT);
    cfg->reconnect_delay_max = (unsigned int)config_get_integer("mqtt-reconnect-delay-max", MQTT_RECONNECT_DELAY_MAX_DEFAULT);
    printf("config: mqtt: server=%s, client=%s\n", cfg->server, cfg->client);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool config_setup(const int argc, char *argv[]) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            config_help(argv[0], config_options, config_options_help, (int)(sizeof(config_options_help) / sizeof(config_options_help[0])));
            exit(EXIT_SUCCESS);
        }

    if (!config_load(CONFIG_FILE_DEFAULT, argc, argv, config_options))
        return false;

    memset(&state, 0, sizeof(state));
    state.mqtt_topic_prefix = config_get_string("mqtt-topic-prefix", MQTT_TOPIC_PREFIX_DEFAULT);
    state.interval_platform = (time_t)config_get_integer("interval-platform", INTERVAL_PLATFORM_DEFAULT);
    state.interval_system = (time_t)config_get_integer("interval-system", INTERVAL_SYSTEM_DEFAULT);
    const char *processes_csv = config_get_string("check-processes", NULL);
    if (processes_csv)
        processes_parse(processes_csv);
    state.check_timesync = config_get_bool("check-timesync", true);
    state.check_gateway = config_get_bool("check-gateway", true);
    state.check_dns = config_get_string("check-dns", NULL);
    state.debug = config_get_bool("debug", false);

    mqtt_config_populate(&state.mqtt_config);

    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static void signal_handler(const int sig __attribute__((unused))) {
    if (running) {
        printf("stopping\n");
        running = false;
    }
}

int main(int argc, char *argv[]) {

    setbuf(stdout, NULL);
    printf("starting (hostmon: host system monitor)\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (!config_setup(argc, argv))
        return EXIT_FAILURE;

    if (!interfaces_discover())
        printf("hostmon: WARNING no network interfaces discovered\n");

    if (!mqtt_begin(&state.mqtt_config))
        return EXIT_FAILURE;

    hostmon_run();

    mqtt_end();

    return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------
