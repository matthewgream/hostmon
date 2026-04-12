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
 *   - "host" (slow): static/rarely changing info — hostname, OS version,
 *     kernel, architecture, boot time. Default 24 hours.
 *   - "platform" (fast): dynamic info — network interface states, IPs,
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

typedef int serial_bits_t;
#define SERIAL_8N1           0

#define MQTT_CONNECT_TIMEOUT 60
#define MQTT_PUBLISH_QOS     0
#define MQTT_PUBLISH_RETAIN  true
#include "mqtt_linux.h"

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

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

#include "config_linux.h"

// clang-format off
const struct option config_options[] = {
    {"help",                        no_argument,       0, 'h'},
    {"config",                      required_argument, 0, 0},
    {"mqtt-client",                 required_argument, 0, 0},
    {"mqtt-server",                 required_argument, 0, 0},
    {"mqtt-topic-prefix",           required_argument, 0, 0},
    {"mqtt-tls-insecure",           required_argument, 0, 0},
    {"mqtt-reconnect-delay",        required_argument, 0, 0},
    {"mqtt-reconnect-delay-max",    required_argument, 0, 0},
    {"interval-platform",           required_argument, 0, 0},
    {"interval-system",             required_argument, 0, 0},
    {"watch-processes",             required_argument, 0, 0},
    {"dns-check-host",              required_argument, 0, 0},
    {"debug",                       required_argument, 0, 0},
    {0, 0, 0, 0}
};

const config_option_help_t config_options_help[] = {
    {"help",                    "Display this help message and exit"},
    {"config",                  "Configuration file path (default: " CONFIG_FILE_DEFAULT ")"},
    {"mqtt-client",             "MQTT client ID (default: " MQTT_CLIENT_DEFAULT ")"},
    {"mqtt-server",             "MQTT server URL (default: " MQTT_SERVER_DEFAULT ")"},
    {"mqtt-topic-prefix",       "MQTT topic prefix (default: " MQTT_TOPIC_PREFIX_DEFAULT ")"},
    {"mqtt-tls-insecure",       "MQTT disable TLS verification (true/false)"},
    {"mqtt-reconnect-delay",    "MQTT reconnect delay in seconds"},
    {"mqtt-reconnect-delay-max","MQTT max reconnect delay in seconds"},
    {"interval-platform",       "Platform info publish interval in seconds (default: 86400)"},
    {"interval-system",         "System info publish interval in seconds (default: 60)"},
    {"watch-processes",         "Comma-separated list of process names to monitor"},
    {"dns-check-host",          "Hostname to resolve for DNS health check"},
    {"debug",                   "Enable debug output (true/false)"},
};
// clang-format on

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define MAX_INTERFACES  8
#define MAX_WATCH_PROCS 16
#define IFACE_NAME_MAX  32
#define PROC_NAME_MAX   64
#define TOPIC_MAX       255

typedef struct {
    char name[IFACE_NAME_MAX];
    bool is_wifi;
    bool was_up;
    char prev_ip[INET_ADDRSTRLEN];
} iface_state_t;

typedef struct {
    char name[PROC_NAME_MAX];
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
    proc_watch_t watch_procs[MAX_WATCH_PROCS];
    int watch_proc_count;
    const char *dns_check_host;
} hostmon_state_t;

static hostmon_state_t state;

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool read_file_line(const char *path, char *buf, size_t size) {
    FILE *f = fopen(path, "r");
    if (!f)
        return false;
    buf[0] = '\0';
    if (fgets(buf, (int)size, f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
    }
    fclose(f);
    return buf[0] != '\0';
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

static char *get_timestamp_iso8601(void) {
    static char buf[32];
    time_t now = time(NULL);
    struct tm *tm = gmtime(&now);
    strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", tm);
    return buf;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static void discover_interfaces(void) {
    state.interface_count = 0;
    DIR *d = opendir("/sys/class/net");
    if (!d)
        return;
    struct dirent *ent;
    while ((ent = readdir(d)) != NULL && state.interface_count < MAX_INTERFACES) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;
        if (strcmp(ent->d_name, "lo") == 0)
            continue;
        iface_state_t *iface = &state.interfaces[state.interface_count];
        size_t nlen = strlen(ent->d_name);
        if (nlen >= sizeof(iface->name))
            nlen = sizeof(iface->name) - 1;
        memcpy(iface->name, ent->d_name, nlen);
        iface->name[nlen] = '\0';
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

static bool get_wifi_ssid(const char *name, char *ssid, size_t size) {
    ssid[0] = '\0';
    char cmd[128], buf[256];
    snprintf(cmd, sizeof(cmd), "iwgetid -r %s 2>/dev/null", name);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    if (fgets(buf, (int)sizeof(buf), f)) {
        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
            buf[--len] = '\0';
        snprintf(ssid, size, "%s", buf);
    }
    pclose(f);
    return ssid[0] != '\0';
}

static bool get_wifi_signal(const char *name, int *signal_dbm) {
    FILE *f = fopen("/proc/net/wireless", "r");
    if (!f)
        return false;
    char line[256];
    // skip header lines
    if (!fgets(line, (int)sizeof(line), f)) {
        fclose(f);
        return false;
    }
    if (!fgets(line, (int)sizeof(line), f)) {
        fclose(f);
        return false;
    }
    bool found = false;
    while (fgets(line, (int)sizeof(line), f)) {
        char iface[IFACE_NAME_MAX];
        int status;
        float link, level;
        if (sscanf(line, " %31[^:]: %d %f %f", iface, &status, &link, &level) >= 4) {
            if (strcmp(iface, name) == 0) {
                *signal_dbm = (int)level;
                found = true;
                break;
            }
        }
    }
    fclose(f);
    return found;
}

static bool get_wifi_frequency(const char *name, char *freq_buf, size_t size) {
    freq_buf[0] = '\0';
    char cmd[128], buf[256];
    snprintf(cmd, sizeof(cmd), "iwgetid -f %s 2>/dev/null", name);
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    if (fgets(buf, (int)sizeof(buf), f)) {
        char *colon = strchr(buf, ':');
        if (colon) {
            colon++;
            while (*colon == ' ')
                colon++;
            size_t len = strlen(colon);
            while (len > 0 && (colon[len - 1] == '\n' || colon[len - 1] == '\r'))
                colon[--len] = '\0';
            snprintf(freq_buf, size, "%s", colon);
        }
    }
    pclose(f);
    return freq_buf[0] != '\0';
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

static bool get_memory_info(uint64_t *total_kb, uint64_t *available_kb, uint64_t *free_kb) {
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return false;
    char line[128];
    int found = 0;
    *total_kb = *available_kb = *free_kb = 0;
    while (fgets(line, (int)sizeof(line), f) && found < 3) {
        uint64_t val;
        if (sscanf(line, "MemTotal: %lu", (unsigned long *)&val) == 1) {
            *total_kb = val;
            found++;
        } else if (sscanf(line, "MemAvailable: %lu", (unsigned long *)&val) == 1) {
            *available_kb = val;
            found++;
        } else if (sscanf(line, "MemFree: %lu", (unsigned long *)&val) == 1) {
            *free_kb = val;
            found++;
        }
    }
    fclose(f);
    return found >= 2;
}

static bool get_load_averages(double *load1, double *load5, double *load15) {
    FILE *f = fopen("/proc/loadavg", "r");
    if (!f)
        return false;
    bool ok = (fscanf(f, "%lf %lf %lf", load1, load5, load15) == 3);
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

static cJSON *build_ntp_json(void) {
    cJSON *ntp = cJSON_CreateObject();

    // try timedatectl (systemd-timesyncd)
    FILE *f = popen("timedatectl show --property=NTPSynchronized --value 2>/dev/null", "r");
    if (f) {
        char buf[32];
        if (fgets(buf, (int)sizeof(buf), f)) {
            size_t len = strlen(buf);
            while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
                buf[--len] = '\0';
            cJSON_AddBoolToObject(ntp, "synchronized", strcmp(buf, "yes") == 0);
        }
        pclose(f);
    }

    // try chronyc for offset
    f = popen("chronyc tracking 2>/dev/null", "r");
    if (f) {
        char line[256];
        bool found_source = false;
        while (fgets(line, (int)sizeof(line), f)) {
            if (!found_source && strncmp(line, "Reference ID", 12) == 0) {
                char *paren = strchr(line, '(');
                if (paren) {
                    char *end = strchr(paren + 1, ')');
                    if (end) {
                        *end = '\0';
                        cJSON_AddStringToObject(ntp, "source", paren + 1);
                        found_source = true;
                    }
                }
            }
            double offset_val;
            if (strncmp(line, "Last offset", 11) == 0) {
                char *colon = strchr(line, ':');
                if (colon && sscanf(colon + 1, " %lf", &offset_val) == 1)
                    cJSON_AddNumberToObject(ntp, "offset_secs", offset_val);
            }
            if (strncmp(line, "Stratum", 7) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    int stratum = atoi(colon + 1);
                    cJSON_AddNumberToObject(ntp, "stratum", stratum);
                }
            }
        }
        pclose(f);
    }

    return ntp;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static void parse_watch_processes(const char *csv) {
    if (!csv || !*csv)
        return;
    char buf[1024];
    size_t csv_len = strlen(csv);
    if (csv_len >= sizeof(buf))
        csv_len = sizeof(buf) - 1;
    memcpy(buf, csv, csv_len);
    buf[csv_len] = '\0';
    char *saveptr = NULL;
    char *tok = strtok_r(buf, ",", &saveptr);
    while (tok && state.watch_proc_count < MAX_WATCH_PROCS) {
        while (*tok == ' ')
            tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ')
            *end-- = '\0';
        if (*tok) {
            proc_watch_t *pw = &state.watch_procs[state.watch_proc_count];
            size_t nlen = strlen(tok);
            if (nlen >= sizeof(pw->name))
                nlen = sizeof(pw->name) - 1;
            memcpy(pw->name, tok, nlen);
            pw->name[nlen] = '\0';
            pw->was_running = false;
            state.watch_proc_count++;
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
}

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
        char comm[PROC_NAME_MAX];
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
                    long page_size = sysconf(_SC_PAGESIZE);
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

static cJSON *build_processes_json(void) {
    if (state.watch_proc_count == 0)
        return NULL;
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < state.watch_proc_count; i++) {
        cJSON *pobj = cJSON_CreateObject();
        cJSON_AddStringToObject(pobj, "name", state.watch_procs[i].name);
        int pid;
        unsigned long rss_kb;
        bool running_now = is_process_running(state.watch_procs[i].name, &pid, &rss_kb);
        cJSON_AddBoolToObject(pobj, "running", running_now);
        if (running_now) {
            cJSON_AddNumberToObject(pobj, "pid", pid);
            cJSON_AddNumberToObject(pobj, "rss_kb", (double)rss_kb);
            // uptime of the process
            char path[PATH_MAX], buf[64];
            snprintf(path, sizeof(path), "/proc/%d/stat", pid);
            FILE *f = fopen(path, "r");
            if (f) {
                // field 22 is starttime in clock ticks
                char stat_buf[1024];
                if (fgets(stat_buf, (int)sizeof(stat_buf), f)) {
                    // skip past the comm field (which may contain spaces/parens)
                    char *close_paren = strrchr(stat_buf, ')');
                    if (close_paren) {
                        unsigned long long starttime = 0;
                        // fields after ')' are: state, ppid, pgrp, session, tty_nr, tpgid,
                        //   flags, minflt, cminflt, majflt, cmajflt, utime, stime, cutime,
                        //   cstime, priority, nice, num_threads, itrealvalue, starttime
                        int n = sscanf(close_paren + 2,
                                       "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %*u "
                                       "%*u %*d %*d %*d %*d %*d %*d %llu",
                                       &starttime);
                        if (n == 1) {
                            long hz = sysconf(_SC_CLK_TCK);
                            if (hz > 0) {
                                struct sysinfo si;
                                if (sysinfo(&si) == 0) {
                                    long proc_uptime = si.uptime - (long)(starttime / (unsigned long long)hz);
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
                char stat_buf2[1024];
                if (fgets(stat_buf2, (int)sizeof(stat_buf2), f)) {
                    char *cp = strrchr(stat_buf2, ')');
                    if (cp) {
                        unsigned long utime = 0, stime = 0;
                        sscanf(cp + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &utime, &stime);
                        long hz = sysconf(_SC_CLK_TCK);
                        if (hz > 0)
                            cJSON_AddNumberToObject(pobj, "cpu_secs", (double)(utime + stime) / (double)hz);
                    }
                }
                fclose(f);
            }
            (void)buf; // unused in this branch
        }
        cJSON_AddItemToArray(arr, pobj);
    }
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool check_process_state_changes(void) {
    bool changed = false;
    for (int i = 0; i < state.watch_proc_count; i++) {
        int pid;
        unsigned long rss_kb;
        bool running_now = is_process_running(state.watch_procs[i].name, &pid, &rss_kb);
        if (running_now != state.watch_procs[i].was_running) {
            printf("hostmon: process '%s' %s -> %s\n", state.watch_procs[i].name, state.watch_procs[i].was_running ? "running" : "stopped", running_now ? "running" : "stopped");
            state.watch_procs[i].was_running = running_now;
            changed = true;
        }
    }
    return changed;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_default_gateway(char *gw_buf, size_t gw_size) {
    gw_buf[0] = '\0';
    FILE *f = fopen("/proc/net/route", "r");
    if (!f)
        return false;
    char line[256];
    // skip header
    if (!fgets(line, (int)sizeof(line), f)) {
        fclose(f);
        return false;
    }
    while (fgets(line, (int)sizeof(line), f)) {
        char iface[32];
        unsigned long dest, gateway;
        if (sscanf(line, "%31s %lx %lx", iface, &dest, &gateway) == 3) {
            if (dest == 0 && gateway != 0) {
                struct in_addr addr;
                addr.s_addr = (in_addr_t)gateway;
                inet_ntop(AF_INET, &addr, gw_buf, (socklen_t)gw_size);
                break;
            }
        }
    }
    fclose(f);
    return gw_buf[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool ping_host(const char *host) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "ping -c1 -W2 %s >/dev/null 2>&1", host);
    return system(cmd) == 0;
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
    int rc = getaddrinfo(hostname, NULL, &hints, &res);
    if (rc != 0)
        return false;
    if (res && res->ai_addr) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        inet_ntop(AF_INET, &sa->sin_addr, result_ip, (socklen_t)result_size);
    }
    freeaddrinfo(res);
    return result_ip[0] != '\0';
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

static cJSON *build_usb_json(void) {
    cJSON *arr = cJSON_CreateArray();
    DIR *d = opendir("/sys/bus/usb/devices");
    if (!d)
        return arr;
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
    return arr;
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
        while (fgets(line, (int)sizeof(line), f)) {
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
        }
        fclose(f);
    }

    // boot time
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        const time_t boot_time = time(NULL) - si.uptime;
        struct tm *bt = gmtime(&boot_time);
        char boot_str[32];
        strftime(boot_str, sizeof(boot_str), "%Y-%m-%dT%H:%M:%SZ", bt);
        cJSON_AddStringToObject(root, "boot_time", boot_str);
    }

    // list discovered interfaces
    cJSON *ifaces = cJSON_AddArrayToObject(root, "interfaces");
    for (int i = 0; i < state.interface_count; i++) {
        cJSON *iobj = cJSON_CreateObject();
        cJSON_AddStringToObject(iobj, "name", state.interfaces[i].name);
        cJSON_AddStringToObject(iobj, "type", state.interfaces[i].is_wifi ? "wifi" : "ethernet");
        char mac[24];
        if (get_iface_mac(state.interfaces[i].name, mac, sizeof(mac)))
            cJSON_AddStringToObject(iobj, "mac", mac);
        cJSON_AddItemToArray(ifaces, iobj);
    }

    return root;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *build_interface_json(const iface_state_t *iface) {
    cJSON *obj = cJSON_CreateObject();
    cJSON_AddStringToObject(obj, "name", iface->name);
    cJSON_AddStringToObject(obj, "type", iface->is_wifi ? "wifi" : "ethernet");

    bool up = get_iface_operstate(iface->name);
    cJSON_AddBoolToObject(obj, "up", up);

    char ip[INET_ADDRSTRLEN];
    if (get_iface_ip(iface->name, ip, sizeof(ip)))
        cJSON_AddStringToObject(obj, "ip", ip);

    int mtu;
    if (get_iface_mtu(iface->name, &mtu))
        cJSON_AddNumberToObject(obj, "mtu", mtu);

    if (!iface->is_wifi) {
        int speed;
        if (get_iface_speed(iface->name, &speed))
            cJSON_AddNumberToObject(obj, "speed_mbps", speed);
        char duplex[16];
        if (get_iface_duplex(iface->name, duplex, sizeof(duplex)))
            cJSON_AddStringToObject(obj, "duplex", duplex);
    } else {
        char ssid[64];
        if (get_wifi_ssid(iface->name, ssid, sizeof(ssid)))
            cJSON_AddStringToObject(obj, "ssid", ssid);
        int sig;
        if (get_wifi_signal(iface->name, &sig))
            cJSON_AddNumberToObject(obj, "signal_dbm", sig);
        char freq[32];
        if (get_wifi_frequency(iface->name, freq, sizeof(freq)))
            cJSON_AddStringToObject(obj, "frequency", freq);
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

static cJSON *build_system_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", get_timestamp_iso8601());
    cJSON_AddStringToObject(root, "type", "system");

    // uptime
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        cJSON_AddNumberToObject(root, "uptime_secs", (double)si.uptime);
        int days = (int)(si.uptime / 86400);
        int hours = (int)((si.uptime % 86400) / 3600);
        int mins = (int)((si.uptime % 3600) / 60);
        char upstr[64];
        snprintf(upstr, sizeof(upstr), "%dd %dh %dm", days, hours, mins);
        cJSON_AddStringToObject(root, "uptime", upstr);
    }

    // cpu temp
    double temp;
    if (get_cpu_temp(&temp))
        cJSON_AddNumberToObject(root, "cpu_temp_c", temp);

    // load
    double l1, l5, l15;
    if (get_load_averages(&l1, &l5, &l15)) {
        cJSON *load = cJSON_AddObjectToObject(root, "load");
        cJSON_AddNumberToObject(load, "1min", l1);
        cJSON_AddNumberToObject(load, "5min", l5);
        cJSON_AddNumberToObject(load, "15min", l15);
    }

    // memory
    uint64_t mem_total, mem_avail, mem_free;
    if (get_memory_info(&mem_total, &mem_avail, &mem_free)) {
        cJSON *mem = cJSON_AddObjectToObject(root, "memory");
        cJSON_AddNumberToObject(mem, "total_kb", (double)mem_total);
        cJSON_AddNumberToObject(mem, "available_kb", (double)mem_avail);
        cJSON_AddNumberToObject(mem, "free_kb", (double)mem_free);
        if (mem_total > 0)
            cJSON_AddNumberToObject(mem, "used_pct", 100.0 * (double)(mem_total - mem_avail) / (double)mem_total);
    }

    // network interfaces
    cJSON *ifaces = cJSON_AddArrayToObject(root, "network");
    for (int i = 0; i < state.interface_count; i++)
        cJSON_AddItemToArray(ifaces, build_interface_json(&state.interfaces[i]));

    // mqtt connection status
    cJSON *mq = cJSON_AddObjectToObject(root, "mqtt");
    cJSON_AddBoolToObject(mq, "connected", mqtt_is_connected());
    cJSON_AddNumberToObject(mq, "disconnects", (double)mqtt_stat_disconnects);

    // disk usage (root filesystem)
    uint64_t disk_total, disk_used, disk_avail;
    if (get_disk_usage("/", &disk_total, &disk_used, &disk_avail)) {
        cJSON *disk = cJSON_AddObjectToObject(root, "disk");
        cJSON_AddNumberToObject(disk, "total_mb", (double)disk_total);
        cJSON_AddNumberToObject(disk, "used_mb", (double)disk_used);
        cJSON_AddNumberToObject(disk, "avail_mb", (double)disk_avail);
        if (disk_total > 0)
            cJSON_AddNumberToObject(disk, "used_pct", 100.0 * (double)disk_used / (double)disk_total);
        cJSON_AddBoolToObject(disk, "readonly", is_filesystem_readonly("/"));
    }

    // NTP sync
    cJSON *ntp = build_ntp_json();
    if (ntp)
        cJSON_AddItemToObject(root, "ntp", ntp);

    // process watchdog
    cJSON *procs = build_processes_json();
    if (procs)
        cJSON_AddItemToObject(root, "processes", procs);

    // default gateway reachability
    cJSON *gw = cJSON_AddObjectToObject(root, "gateway");
    char gw_ip[INET_ADDRSTRLEN];
    if (get_default_gateway(gw_ip, sizeof(gw_ip))) {
        cJSON_AddStringToObject(gw, "ip", gw_ip);
        cJSON_AddBoolToObject(gw, "reachable", ping_host(gw_ip));
    } else {
        cJSON_AddStringToObject(gw, "ip", "none");
        cJSON_AddBoolToObject(gw, "reachable", false);
    }

    // DNS resolution check
    if (state.dns_check_host && *state.dns_check_host) {
        cJSON *dns = cJSON_AddObjectToObject(root, "dns");
        cJSON_AddStringToObject(dns, "check_host", state.dns_check_host);
        char resolved_ip[INET_ADDRSTRLEN];
        bool resolved = check_dns_resolution(state.dns_check_host, resolved_ip, sizeof(resolved_ip));
        cJSON_AddBoolToObject(dns, "ok", resolved);
        if (resolved)
            cJSON_AddStringToObject(dns, "resolved_ip", resolved_ip);
    }

    // USB devices
    cJSON *usb = build_usb_json();
    if (usb)
        cJSON_AddItemToObject(root, "usb", usb);

    return root;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool publish_json(const char *subtopic, cJSON *json) {
    if (!json)
        return false;
    char *str = cJSON_PrintUnformatted(json);
    if (!str) {
        cJSON_Delete(json);
        return false;
    }
    char topic[TOPIC_MAX];
    char hostname[64];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        snprintf(hostname, sizeof(hostname), "unknown");
    snprintf(topic, sizeof(topic), "%s/%s/%s", state.mqtt_topic_prefix, hostname, subtopic);

    bool ok = mqtt_send(topic, str, (int)strlen(str));
    if (state.debug)
        printf("hostmon: publish %s (%d bytes) -> %s\n", subtopic, (int)strlen(str), ok ? "ok" : "FAILED");
    free(str);
    cJSON_Delete(json);
    return ok;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool check_network_state_changes(void) {
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
// -----------------------------------------------------------------------------------------------------------------------------------------

static time_t intervalable(const time_t interval, time_t *last) {
    time_t now = time(NULL);
    if (*last == 0) {
        *last = now;
        return 0;
    }
    if ((now - *last) > interval) {
        const time_t diff = now - *last;
        *last = now;
        return diff;
    }
    return 0;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void hostmon_run(void) {

    printf("hostmon: running (platform=%lds, system=%lds, interfaces=%d, "
           "procs=%d, dns=%s, topic=%s)\n",
           (long)state.interval_platform, (long)state.interval_system, state.interface_count, state.watch_proc_count, state.dns_check_host ? state.dns_check_host : "none", state.mqtt_topic_prefix);

    for (int i = 0; i < state.interface_count; i++) {
        iface_state_t *iface = &state.interfaces[i];
        iface->was_up = get_iface_operstate(iface->name);
        get_iface_ip(iface->name, iface->prev_ip, sizeof(iface->prev_ip));
    }

    for (int i = 0; i < state.watch_proc_count; i++) {
        int pid;
        unsigned long rss_kb;
        state.watch_procs[i].was_running = is_process_running(state.watch_procs[i].name, &pid, &rss_kb);
        printf("hostmon: watching process '%s' (%s)\n", state.watch_procs[i].name, state.watch_procs[i].was_running ? "running" : "not found");
    }

    publish_json("platform", build_platform_json());
    state.interval_platform_last = time(NULL);
    publish_json("system", build_system_json());
    state.interval_system_last = time(NULL);

    while (running) {

        if (state.mqtt_config.use_synchronous)
            mqtt_loop(1000);
        else
            usleep(1000000); /* 1 second */

        if (!running)
            break;

        bool urgent = false;

        if (check_network_state_changes()) {
            printf("hostmon: network state change, publishing immediately\n");
            urgent = true;
        }
        if (check_process_state_changes()) {
            printf("hostmon: process state change, publishing immediately\n");
            urgent = true;
        }
        if (urgent) {
            publish_json("system", build_system_json());
            state.interval_system_last = time(NULL);
        }

        if (intervalable(state.interval_platform, &state.interval_platform_last))
            publish_json("platform", build_platform_json());
        if (intervalable(state.interval_system, &state.interval_system_last))
            publish_json("system", build_system_json());
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
    state.debug = config_get_bool("debug", false);
    state.dns_check_host = config_get_string("dns-check-host", NULL);

    const char *watch_csv = config_get_string("watch-processes", NULL);
    if (watch_csv)
        parse_watch_processes(watch_csv);

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

    int ret = EXIT_FAILURE;

    setbuf(stdout, NULL);
    printf("starting (hostmon: host system monitor)\n");
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    if (!config_setup(argc, argv))
        goto end_all;

    discover_interfaces();
    if (state.interface_count == 0)
        printf("hostmon: WARNING no network interfaces discovered\n");

    if (!mqtt_begin(&state.mqtt_config))
        goto end_all;

    hostmon_run();
    ret = EXIT_SUCCESS;

    mqtt_end();
end_all:
    return ret;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------
