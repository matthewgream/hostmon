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
#include <stdarg.h>

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

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

__attribute__((format(printf, 3, 4))) static const char *snprintf_inline(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, size, fmt, ap);
    va_end(ap);
    return buf;
}

static const char *strtime_iso8601(const time_t t) {
    static char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", gmtime(&t));
    return ts;
}

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

static bool read_file_string(const char *path, char *line_buf, size_t line_size) {
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
    if (!read_file_string(path, buf, sizeof(buf)))
        return false;
    char *end;
    *val = strtoull(buf, &end, 10);
    return *end == '\0' || *end == '\n';
}

static bool read_pipe_string(const char *cmd, char *line_buf, size_t line_size) {
    FILE *f = popen(cmd, "r");
    if (!f)
        return false;
    line_buf[0] = '\0';
    if (fgets(line_buf, (int)line_size, f))
        string_cleanup(line_buf);
    pclose(f);
    return line_buf[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

volatile bool running = true;

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define MQTT_CONNECT_TIMEOUT 60
#define MQTT_PUBLISH_QOS     0
#define MQTT_PUBLISH_RETAIN  true
#include "mqtt_linux.h"

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define MQTTTOPICS_MAX_SUBS            16
#define MQTTTOPICS_TOPIC_MAX           255
#define MQTTTOPICS_HASHES_MAX          2048
#define MQTTTOPICS_BUCKETS_1S          60
#define MQTTTOPICS_BUCKETS_15M         288
#define MQTTTOPICS_BUCKET_15M_SECS     900
#define MQTTTOPICS_SERVER_DEFAULT      "mqtt://localhost:1883"
#define MQTTTOPICS_CLIENT_SUFFIX       "-check"
#define MQTTTOPICS_RECONNECT_DELAY     5
#define MQTTTOPICS_RECONNECT_DELAY_MAX 60

// -----------------------------------------------------------------------------------------------------------------------------------------

typedef struct {
    char topic[MQTTTOPICS_TOPIC_MAX + 1];
    bool subscribed;
    uint64_t messages;
    uint64_t bytes;
    time_t last_message_time;
    uint32_t topic_hashes[MQTTTOPICS_HASHES_MAX];
    int topic_hash_count;
    bool topic_hashes_full;
    uint32_t buckets_1s[MQTTTOPICS_BUCKETS_1S];
    uint32_t buckets_15m[MQTTTOPICS_BUCKETS_15M];
    time_t bucket_1s_last_sec;
    time_t bucket_15m_last_slot;
} mqtttopics_sub_t;

typedef struct {
    bool enabled;
    char client_id_buf[64];
    char server_buf[255 + 16]; // XXX
    mqtt_config_t mqtt_config;
    mqtt_context_t mqtt_ctx;
    int subscription_count;
    mqtttopics_sub_t subscriptions[MQTTTOPICS_MAX_SUBS];
} mqtttopics_state_t;

// -----------------------------------------------------------------------------------------------------------------------------------------

static uint32_t __mqtttopics_hash_create(const char *s) {
    uint32_t h = 2166136261u; // FNV offset basis
    while (*s) {
        h ^= (uint32_t)(uint8_t)*s;
        h *= 16777619u;
        s++;
    }
    return h;
}

static int __mqtttopics_hash_search(const uint32_t *arr, int n, uint32_t key) {
    int lo = 0, hi = n;
    while (lo < hi) {
        const int mid = (lo + hi) >> 1;
        if (arr[mid] < key)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}

static bool __mqtttopics_hash_insert(mqtttopics_sub_t *sub, uint32_t key) {
    const int pos = __mqtttopics_hash_search(sub->topic_hashes, sub->topic_hash_count, key);
    if (pos < sub->topic_hash_count && sub->topic_hashes[pos] == key)
        return false;
    if (sub->topic_hash_count >= MQTTTOPICS_HASHES_MAX) {
        sub->topic_hashes_full = true;
        return false;
    }
    if (pos < sub->topic_hash_count)
        memmove(&sub->topic_hashes[pos + 1], &sub->topic_hashes[pos], (size_t)(sub->topic_hash_count - pos) * sizeof(uint32_t));
    sub->topic_hashes[pos] = key;
    sub->topic_hash_count++;
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtttopics_bucket_advance_1s(mqtttopics_sub_t *sub, time_t now) {
    if (sub->bucket_1s_last_sec == 0)
        sub->bucket_1s_last_sec = now;
    else {
        const time_t diff = now - sub->bucket_1s_last_sec;
        if (diff > 0) {
            if (diff >= MQTTTOPICS_BUCKETS_1S)
                memset(sub->buckets_1s, 0, sizeof(sub->buckets_1s));
            else
                for (time_t i = 1; i <= diff; i++)
                    sub->buckets_1s[(size_t)((sub->bucket_1s_last_sec + i) % MQTTTOPICS_BUCKETS_1S)] = 0;
            sub->bucket_1s_last_sec = now;
        }
    }
}

static void __mqtttopics_bucket_advance_15m(mqtttopics_sub_t *sub, time_t now) {
    if (sub->bucket_15m_last_slot == 0)
        sub->bucket_15m_last_slot = (now / MQTTTOPICS_BUCKET_15M_SECS);
    else {
        const time_t diff = (now / MQTTTOPICS_BUCKET_15M_SECS) - sub->bucket_15m_last_slot;
        if (diff > 0) {
            if (diff >= MQTTTOPICS_BUCKETS_15M)
                memset(sub->buckets_15m, 0, sizeof(sub->buckets_15m));
            else
                for (time_t i = 1; i <= diff; i++)
                    sub->buckets_15m[(size_t)((sub->bucket_15m_last_slot + i) % MQTTTOPICS_BUCKETS_15M)] = 0;
            sub->bucket_15m_last_slot = (now / MQTTTOPICS_BUCKET_15M_SECS);
        }
    }
}

static void __mqtttopics_bucket_record(mqtttopics_sub_t *sub, time_t now) {
    __mqtttopics_bucket_advance_1s(sub, now);
    sub->buckets_1s[(size_t)(now % MQTTTOPICS_BUCKETS_1S)]++;
    __mqtttopics_bucket_advance_15m(sub, now);
    sub->buckets_15m[(size_t)((now / MQTTTOPICS_BUCKET_15M_SECS) % MQTTTOPICS_BUCKETS_15M)]++;
}

#define _MIN(x, y) ((x) < (y) ? (x) : (y))
static double __mqtttopics_rate_window(mqtttopics_sub_t *sub, time_t now, int window_secs) {
    if (window_secs <= MQTTTOPICS_BUCKETS_1S) {
        __mqtttopics_bucket_advance_1s(sub, now);
        uint64_t sum = 0;
        for (int i = 0; i < window_secs && (now - i) >= 0; i++)
            sum += sub->buckets_1s[(size_t)((now - i) % MQTTTOPICS_BUCKETS_1S)];
        return (double)sum / (double)window_secs;
    } else {
        __mqtttopics_bucket_advance_15m(sub, now);
        const int slots = _MIN((window_secs + MQTTTOPICS_BUCKET_15M_SECS - 1) / MQTTTOPICS_BUCKET_15M_SECS, MQTTTOPICS_BUCKETS_15M);
        uint64_t sum = 0;
        for (int i = 0; i < slots && ((now / MQTTTOPICS_BUCKET_15M_SECS) - i) >= 0; i++)
            sum += sub->buckets_15m[(size_t)(((now / MQTTTOPICS_BUCKET_15M_SECS) - i) % MQTTTOPICS_BUCKETS_15M)];
        return (double)sum / (double)(slots * MQTTTOPICS_BUCKET_15M_SECS);
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtttopics_message_handler(void *user_data, const char *topic, const unsigned char *payload __attribute__((unused)), int payloadlen) {
    mqtttopics_state_t *state = (mqtttopics_state_t *)user_data;
    if (!state || !topic)
        return;
    const time_t now = time(NULL);
    const uint32_t hash = __mqtttopics_hash_create(topic);
    for (int i = 0; i < state->subscription_count; i++) {
        mqtttopics_sub_t *sub = &state->subscriptions[i];
        bool match = false;
        if (mosquitto_topic_matches_sub(sub->topic, topic, &match) == MOSQ_ERR_SUCCESS && match) {
            sub->messages++;
            sub->bytes += (uint64_t)(payloadlen > 0 ? payloadlen : 0);
            sub->last_message_time = now;
            __mqtttopics_hash_insert(sub, hash);
            __mqtttopics_bucket_record(sub, now);
        }
    }
}

static void __mqtttopics_connect_handler(void *user_data, bool connected) {
    mqtttopics_state_t *state = (mqtttopics_state_t *)user_data;
    if (!state)
        return;
    for (int i = 0; i < state->subscription_count; i++)
        state->subscriptions[i].subscribed = connected && mqtt_subscribe(&state->mqtt_ctx, state->subscriptions[i].topic, 0);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtttopics_setup(mqtttopics_state_t *state, const char *config_value, const char *client_base) {
    memset(state, 0, sizeof(*state));
    if (!config_value || !*config_value)
        return false;
    char buf[255]; // XXX
    size_t cv_len = strlen(config_value);
    if (cv_len >= sizeof(buf))
        cv_len = sizeof(buf) - 1;
    memcpy(buf, config_value, cv_len);
    buf[cv_len] = '\0';
    char *server_part = NULL, *topics_part = NULL;
    char *semi = strchr(buf, ';');
    if (semi) {
        *semi = '\0';
        server_part = buf;
        topics_part = semi + 1;
    } else
        topics_part = buf;
    if (server_part && *server_part) {
        const char *src = server_part;
        if (strncmp(src, "mqtt://", 7) != 0 && strncmp(src, "mqtts://", 8) != 0)
            snprintf(state->server_buf, sizeof(state->server_buf), "mqtt://%s", src);
        else
            snprintf(state->server_buf, sizeof(state->server_buf), "%s", src);
    } else
        snprintf(state->server_buf, sizeof(state->server_buf), "%s", MQTTTOPICS_SERVER_DEFAULT);
    state->mqtt_config.server = state->server_buf;
    state->mqtt_config.client = snprintf_inline(state->client_id_buf, sizeof(state->client_id_buf), "%s%s", client_base ? client_base : "hostmon", MQTTTOPICS_CLIENT_SUFFIX);
    state->mqtt_config.use_synchronous = true;
    state->mqtt_config.tls_insecure = false;
    state->mqtt_config.reconnect_delay = MQTTTOPICS_RECONNECT_DELAY;
    state->mqtt_config.reconnect_delay_max = MQTTTOPICS_RECONNECT_DELAY_MAX;
    snprintf(state->mqtt_ctx.log_prefix, sizeof(state->mqtt_ctx.log_prefix), "check-topics");
    char *saveptr = NULL, *tok = strtok_r(topics_part, ",", &saveptr);
    while (tok && state->subscription_count < MQTTTOPICS_MAX_SUBS) {
        while (*tok == ' ')
            tok++;
        char *end = tok + strlen(tok) - 1;
        while (end > tok && *end == ' ')
            *end-- = '\0';
        if (*tok) {
            mqtttopics_sub_t *sub = &state->subscriptions[state->subscription_count];
            const size_t tl = strlen(tok);
            if (tl <= MQTTTOPICS_TOPIC_MAX) {
                memcpy(sub->topic, tok, tl);
                sub->topic[tl] = '\0';
                state->subscription_count++;
            } else
                fprintf(stderr, "check-topics: topic too long, skipping: '%s'\n", tok);
        }
        tok = strtok_r(NULL, ",", &saveptr);
    }
    if (state->subscription_count == 0) {
        fprintf(stderr, "check-topics: no topics configured, disabling\n");
        return false;
    }
    state->enabled = true;
    printf("check-topics: configured (server='%s', client='%s', topics=%d)\n", state->server_buf, state->client_id_buf, state->subscription_count);
    for (int i = 0; i < state->subscription_count; i++)
        printf("check-topics:   topic[%d]='%s'\n", i, state->subscriptions[i].topic);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtttopics_init(mqtttopics_state_t *state) {
    if (!state->enabled)
        return false;
    mqtt_set_handlers(&state->mqtt_ctx, __mqtttopics_message_handler, __mqtttopics_connect_handler, state);
    if (!mqtt_begin(&state->mqtt_ctx, &state->mqtt_config)) {
        fprintf(stderr, "check-topics: connect failed, will retry in background\n");
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void mqtttopics_loop(mqtttopics_state_t *state, int timeout_ms) {
    if (!state->enabled)
        return;
    mqtt_loop(&state->mqtt_ctx, timeout_ms);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void mqtttopics_term(mqtttopics_state_t *state) {
    if (!state->enabled)
        return;
    mqtt_end(&state->mqtt_ctx);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *mqtttopics_build_json(mqtttopics_state_t *state) {
    if (!state->enabled)
        return NULL;
    cJSON *arr = cJSON_CreateArray();
    const time_t now = time(NULL);
    for (int i = 0; i < state->subscription_count; i++) {
        mqtttopics_sub_t *sub = &state->subscriptions[i];
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "topic", sub->topic);
        cJSON_AddBoolToObject(obj, "subscribed", sub->subscribed);
        cJSON *sizes = cJSON_AddObjectToObject(obj, "sizes");
        cJSON_AddNumberToObject(sizes, "topics", (double)sub->topic_hash_count);
        if (sub->topic_hashes_full)
            cJSON_AddBoolToObject(sizes, "topics_truncated", true);
        cJSON_AddNumberToObject(sizes, "messages", (double)sub->messages);
        cJSON_AddNumberToObject(sizes, "bytes", (double)sub->bytes);
        if (sub->last_message_time > 0)
            cJSON_AddStringToObject(obj, "last_message_time", strtime_iso8601(sub->last_message_time));
        cJSON *rates = cJSON_AddObjectToObject(obj, "rates");
        cJSON *messages = cJSON_AddObjectToObject(rates, "messages");
        cJSON_AddNumberToObject(messages, "60s", __mqtttopics_rate_window(sub, now, 60));
        cJSON_AddNumberToObject(messages, "15m", __mqtttopics_rate_window(sub, now, 15 * 60));
        cJSON_AddNumberToObject(messages, "1h", __mqtttopics_rate_window(sub, now, 60 * 60));
        cJSON_AddNumberToObject(messages, "3h", __mqtttopics_rate_window(sub, now, 3 * 60 * 60));
        cJSON_AddNumberToObject(messages, "12h", __mqtttopics_rate_window(sub, now, 12 * 60 * 60));
        cJSON_AddNumberToObject(messages, "24h", __mqtttopics_rate_window(sub, now, 24 * 60 * 60));
        cJSON_AddNumberToObject(messages, "72h", __mqtttopics_rate_window(sub, now, 72 * 60 * 60));
        cJSON_AddItemToArray(arr, obj);
    }
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#define HOSTMON_VERSION                  "1.0.0"

#define CONFIG_FILE_DEFAULT              "hostmon.cfg"

#define MQTT_CLIENT_DEFAULT              "hostmon"
#define MQTT_SERVER_DEFAULT              "mqtt://localhost"
#define MQTT_TLS_DEFAULT                 false
#define MQTT_SYNCHRONOUS_DEFAULT         true
#define MQTT_TOPIC_PREFIX_DEFAULT        "system/monitor"
#define MQTT_RECONNECT_DELAY_DEFAULT     5
#define MQTT_RECONNECT_DELAY_MAX_DEFAULT 60

#define INTERVAL_PLATFORM_DEFAULT        (24 * 60 * 60)
#define INTERVAL_SYSTEM_DEFAULT          (5 * 60)

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
    {"check-resolve",                   required_argument, 0, 0},
    {"check-topics",                    required_argument, 0, 0},
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
    {"mqtt-reconnect-delay",            "MQTT reconnect delay in seconds (default: 5)"},
    {"mqtt-reconnect-delay-max",        "MQTT max reconnect delay in seconds (default: 60)"},
    {"interval-platform",               "Platform info publish interval in seconds (default: 86400)"},
    {"interval-system",                 "System info publish interval in seconds (default: 300)"},
    {"check-processes",                 "Check list of processes (comma-separated) (default: unspecified)"},
    {"check-timesync",                  "Check time synchronisation (default: true)"},
    {"check-gateway",                   "Check ping to network gateway (default: true)"},
    {"check-resolve",                   "Check resolution of specified DNS host (default: unspecified)"},
    {"check-topics",                    "Check MQTT topics: [server;]topic1,topic2,... (default: unspecified)"},
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
    mqtt_context_t mqtt_ctx;
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
    const char *check_resolve;
    mqtttopics_state_t check_topics;
} hostmon_state_t;

static hostmon_state_t state;

static time_t last_publish_time = 0;

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool ping_host(const char *host, double *rtt_ms) {
    if (rtt_ms)
        *rtt_ms = -1.0;
    char cmd[160];
    FILE *f = popen(snprintf_inline(cmd, sizeof(cmd), "ping -c1 -W2 %s 2>/dev/null", host), "r");
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

static bool get_iface_operstate(const char *name) {
    char path[PATH_MAX], buf[32];
    if (!read_file_string(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/operstate", name), buf, sizeof(buf)))
        return false;
    return strcmp(buf, "up") == 0;
}

static bool get_iface_ip(const char *name, char *ip_buf, size_t ip_size) {
    ip_buf[0] = '\0';
    struct ifaddrs *ifas, *ifa;
    if (getifaddrs(&ifas) != 0)
        return false;
    for (ifa = ifas; ifa; ifa = ifa->ifa_next) {
        // skip non internet
        if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strcmp(ifa->ifa_name, name) == 0) {
            inet_ntop(AF_INET, &((struct sockaddr_in *)ifa->ifa_addr)->sin_addr, ip_buf, (socklen_t)ip_size);
            break;
        }
    }
    freeifaddrs(ifas);
    return ip_buf[0] != '\0';
}

static bool get_iface_mac(const char *name, char *mac_buf, size_t mac_size) {
    char path[PATH_MAX];
    if (!read_file_string(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/address", name), mac_buf, mac_size))
        return false;
    return mac_buf[0] != '\0';
}

static bool get_iface_speed(const char *name, int *speed) {
    char path[PATH_MAX], buf[32];
    if (!read_file_string(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/speed", name), buf, sizeof(buf)))
        return false;
    *speed = atoi(buf);
    return *speed > 0;
}

static bool get_iface_duplex(const char *name, char *duplex_buf, size_t duplex_size) {
    char path[PATH_MAX];
    if (!read_file_string(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/duplex", name), duplex_buf, duplex_size))
        return false;
    return duplex_buf[0] != '\0';
}

static bool get_iface_counter(const char *name, const char *counter, uint64_t *val) {
    char path[PATH_MAX];
    return read_file_uint64(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/statistics/%s", name, counter), val);
}

static bool get_iface_mtu(const char *name, int *mtu) {
    char path[PATH_MAX], buf[32];
    if (!read_file_string(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/mtu", name), buf, sizeof(buf)))
        return false;
    *mtu = atoi(buf);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_wifi_ssid(const char *name, char *ssid_buf, size_t ssid_size) {
    char cmd[128];
    if (!read_pipe_string(snprintf_inline(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | awk '/ssid/{print $2}'", name), ssid_buf, ssid_size))
        return false;
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
    char cmd[128];
    if (!read_pipe_string(snprintf_inline(cmd, sizeof(cmd), "iw dev %s info 2>/dev/null | awk '/channel/{print $2\"ch \"$5\" MHz\"}'", name), freq_buf, freq_size))
        return false;
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
            iface->is_wifi = (access(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/wireless", ent->d_name), F_OK) == 0);
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

    int val_int;
    uint64_t val_uint64;
    char path[PATH_MAX], val_str[PATH_MAX];

    cJSON_AddBoolToObject(obj, "up", get_iface_operstate(iface->name));

    if (get_iface_ip(iface->name, val_str, sizeof(val_str)))
        cJSON_AddStringToObject(obj, "ip", val_str);

    if (get_iface_mtu(iface->name, &val_int))
        cJSON_AddNumberToObject(obj, "mtu", val_int);

    if (read_file_uint64(snprintf_inline(path, sizeof(path), "/sys/class/net/%s/carrier_changes", iface->name), &val_uint64))
        cJSON_AddNumberToObject(obj, "carrier_changes", (double)val_uint64);

    if (!iface->is_wifi) {
        if (get_iface_speed(iface->name, &val_int))
            cJSON_AddNumberToObject(obj, "speed_mbps", val_int);
        if (get_iface_duplex(iface->name, val_str, sizeof(val_str)))
            cJSON_AddStringToObject(obj, "duplex", val_str);
    } else {
        if (get_wifi_ssid(iface->name, val_str, sizeof(val_str)))
            cJSON_AddStringToObject(obj, "ssid", val_str);
        if (get_wifi_signal(iface->name, &val_int))
            cJSON_AddNumberToObject(obj, "signal_dbm", val_int);
        if (get_wifi_frequency(iface->name, val_str, sizeof(val_str)))
            cJSON_AddStringToObject(obj, "frequency", val_str);
    }

    if (get_iface_counter(iface->name, "rx_bytes", &val_uint64))
        cJSON_AddNumberToObject(obj, "rx_bytes", (double)val_uint64);
    if (get_iface_counter(iface->name, "tx_bytes", &val_uint64))
        cJSON_AddNumberToObject(obj, "tx_bytes", (double)val_uint64);
    if (get_iface_counter(iface->name, "rx_packets", &val_uint64))
        cJSON_AddNumberToObject(obj, "rx_packets", (double)val_uint64);
    if (get_iface_counter(iface->name, "tx_packets", &val_uint64))
        cJSON_AddNumberToObject(obj, "tx_packets", (double)val_uint64);
    if (get_iface_counter(iface->name, "rx_errors", &val_uint64))
        cJSON_AddNumberToObject(obj, "rx_errors", (double)val_uint64);
    if (get_iface_counter(iface->name, "tx_errors", &val_uint64))
        cJSON_AddNumberToObject(obj, "tx_errors", (double)val_uint64);
    if (get_iface_counter(iface->name, "rx_dropped", &val_uint64))
        cJSON_AddNumberToObject(obj, "rx_dropped", (double)val_uint64);
    if (get_iface_counter(iface->name, "tx_dropped", &val_uint64))
        cJSON_AddNumberToObject(obj, "tx_dropped", (double)val_uint64);

    return obj;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *network_build_json(void) {
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < state.interface_count; i++)
        cJSON_AddItemToArray(arr, interfaces_build_json(&state.interfaces[i]));
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *timesync_build_json(void) {
    cJSON *timesync = cJSON_CreateObject();

    // try timedatectl (systemd-timesyncd)
    char buf[32];
    if (read_pipe_string("timedatectl show --property=NTPSynchronized --value 2>/dev/null", buf, sizeof(buf)))
        cJSON_AddBoolToObject(timesync, "synchronized", strcmp(buf, "yes") == 0);

    // try chronyc for offset
    FILE *f = popen("chronyc tracking 2>/dev/null", "r");
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
    DIR *d = opendir("/proc");
    if (!d)
        return false;
    struct dirent *ent;
    bool found = false;
    while ((ent = readdir(d)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0]))
            continue;
        char path[PATH_MAX], comm[PROCESS_NAME_MAX];
        if (read_file_string(snprintf_inline(path, sizeof(path), "/proc/%s/comm", ent->d_name), comm, sizeof(comm))) {
            if (strcmp(comm, name) == 0) {
                *rss_kb_out = 0;
                *pid_out = atoi(ent->d_name);
                // read RSS from /proc/PID/statm (second field, in pages)
                FILE *f = fopen(snprintf_inline(path, sizeof(path), "/proc/%s/statm", ent->d_name), "r");
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
            if (read_file_string(snprintf_inline(path, sizeof(path), "/proc/%d/stat", pid), buf, sizeof(buf))) {
                // field 22 is starttime in clock ticks
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
            // cpu time (utime + stime)
            if (read_file_string(snprintf_inline(path, sizeof(path), "/proc/%d/stat", pid), buf, sizeof(buf))) {
                const char *cp = strrchr(buf, ')');
                if (cp) {
                    unsigned long utime = 0, stime = 0;
                    sscanf(cp + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %lu %lu", &utime, &stime);
                    const long hz = sysconf(_SC_CLK_TCK);
                    if (hz > 0)
                        cJSON_AddNumberToObject(pobj, "cpu_secs", (double)(utime + stime) / (double)hz);
                }
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
        uint64_t val;
        if (read_file_uint64(snprintf_inline(path, sizeof(path), "/sys/class/thermal/thermal_zone%d/temp", i), &val)) {
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

static cJSON *memory_build_json(void) {
    uint64_t mem_total_kb, mem_available_kb, mem_free_kb, swap_total_kb, swap_free_kb;
    if (!get_memory_info(&mem_total_kb, &mem_available_kb, &mem_free_kb, &swap_total_kb, &swap_free_kb))
        return NULL;
    cJSON *mem = cJSON_CreateObject();
    cJSON_AddNumberToObject(mem, "total_kb", (double)mem_total_kb);
    cJSON_AddNumberToObject(mem, "available_kb", (double)mem_available_kb);
    cJSON_AddNumberToObject(mem, "free_kb", (double)mem_free_kb);
    if (mem_total_kb > 0)
        cJSON_AddNumberToObject(mem, "used_pct", round(1000.0 * (double)(mem_total_kb - mem_available_kb) / (double)mem_total_kb) / 10.0);
    cJSON_AddNumberToObject(mem, "swap_total_kb", (double)swap_total_kb);
    cJSON_AddNumberToObject(mem, "swap_free_kb", (double)swap_free_kb);
    if (swap_total_kb > 0)
        cJSON_AddNumberToObject(mem, "swap_used_pct", round(1000.0 * (double)(swap_total_kb - swap_free_kb) / (double)swap_total_kb) / 10.0);
    return mem;
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

static bool get_cpu_governor(char *buf, size_t size) {
    return read_file_string("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor", buf, size);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *cpu_build_json(void) {
    double temp_c;
    const bool have_temp = get_cpu_temp(&temp_c);
    uint64_t cpu_cur_khz, cpu_max_khz;
    const bool have_freq = get_cpu_freq(&cpu_cur_khz, &cpu_max_khz);
    char governor[32];
    const bool have_governor = get_cpu_governor(governor, sizeof(governor));
    uint64_t rpi_flags = 0;
    const bool have_rpi = get_rpi_throttled(&rpi_flags);
    if (!have_temp && !have_freq && !have_governor && !have_rpi)
        return NULL;
    cJSON *cpu = cJSON_CreateObject();
    if (have_temp)
        cJSON_AddNumberToObject(cpu, "temp_c", round(temp_c * 10.0) / 10.0);
    if (have_freq) {
        if (cpu_cur_khz > 0)
            cJSON_AddNumberToObject(cpu, "cur_khz", (double)cpu_cur_khz);
        if (cpu_max_khz > 0)
            cJSON_AddNumberToObject(cpu, "max_khz", (double)cpu_max_khz);
    }
    if (have_governor)
        cJSON_AddStringToObject(cpu, "governor", governor);
    if (have_freq) {
        bool throttled = false;
        if (have_rpi && rpi_flags != 0)
            throttled = (rpi_flags & 0x6) != 0;
        else if (cpu_cur_khz > 0 && cpu_max_khz > 0 && cpu_cur_khz < cpu_max_khz)
            throttled = have_governor && strcmp(governor, "performance") == 0;
        cJSON_AddBoolToObject(cpu, "throttled", throttled);
    }
    if (have_rpi) {
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
    return cpu;
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
        if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/block/%s/device/life_time", ent->d_name), buf, sizeof(buf))) {
            unsigned int type_a = 0, type_b = 0;
            if (sscanf(buf, "%x %x", &type_a, &type_b) >= 1) {
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
                if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/block/%s/device/pre_eol_info", ent->d_name), buf, sizeof(buf))) {
                    unsigned int eol = 0;
                    if (sscanf(buf, "%x", &eol) == 1)
                        cJSON_AddNumberToObject(dev, "pre_eol_info", (double)eol);
                }
                cJSON_AddItemToArray(arr, dev);
            }
        }
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

static cJSON *load_build_json(void) {
    double load_1min, load_5min, load_15min;
    if (!get_load_averages(&load_1min, &load_5min, &load_15min))
        return NULL;
    cJSON *load = cJSON_CreateObject();
    cJSON_AddNumberToObject(load, "1min", load_1min);
    cJSON_AddNumberToObject(load, "5min", load_5min);
    cJSON_AddNumberToObject(load, "15min", load_15min);
    return load;
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

static cJSON *disk_build_json(void) {
    uint64_t disk_total_mb, disk_used_mb, disk_avail_mb;
    if (!get_disk_usage("/", &disk_total_mb, &disk_used_mb, &disk_avail_mb))
        return NULL;
    cJSON *disk = cJSON_CreateObject();
    cJSON_AddNumberToObject(disk, "total_mb", (double)disk_total_mb);
    cJSON_AddNumberToObject(disk, "used_mb", (double)disk_used_mb);
    cJSON_AddNumberToObject(disk, "avail_mb", (double)disk_avail_mb);
    if (disk_total_mb > 0)
        cJSON_AddNumberToObject(disk, "used_pct", round(1000.0 * (double)disk_used_mb / (double)disk_total_mb) / 10.0);
    cJSON_AddBoolToObject(disk, "readonly", is_filesystem_readonly("/"));
    return disk;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool check_resolve_dns_name(const char *hostname, char *result_ip, size_t result_size) {
    result_ip[0] = '\0';
    if (!hostname || !*hostname)
        return false;
    const struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM };
    struct addrinfo *res = NULL;
    if (getaddrinfo(hostname, NULL, &hints, &res) != 0)
        return false;
    if (res && res->ai_addr)
        inet_ntop(AF_INET, &((const struct sockaddr_in *)res->ai_addr)->sin_addr, result_ip, (socklen_t)result_size);
    freeaddrinfo(res);
    return result_ip[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *resolve_build_json(void) {
    cJSON *resolve = cJSON_CreateObject();
    cJSON_AddStringToObject(resolve, "hostname", state.check_resolve);
    char resolved_ip[INET_ADDRSTRLEN];
    const bool resolved = check_resolve_dns_name(state.check_resolve, resolved_ip, sizeof(resolved_ip));
    cJSON_AddBoolToObject(resolve, "ok", resolved);
    if (resolved)
        cJSON_AddStringToObject(resolve, "ip", resolved_ip);
    return resolve;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static bool get_default_gateway(char *gw_buf, size_t gw_size, char *iface_buf, size_t iface_len) {
    gw_buf[0] = '\0';
    if (iface_buf && iface_len > 0)
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
                if (iface_buf && iface_len > 0)
                    string_memcpy(iface_buf, iface_len, iface);
                break;
            }
    }
    fclose(f);
    return gw_buf[0] != '\0';
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *gateway_build_json(void) {
    cJSON *gateway = cJSON_CreateObject();
    char gw_ip[INET_ADDRSTRLEN], gw_if[INTERFACE_NAME_MAX];
    if (get_default_gateway(gw_ip, sizeof(gw_ip), gw_if, sizeof(gw_if))) {
        cJSON_AddStringToObject(gateway, "ip", gw_ip);
        if (gw_if[0])
            cJSON_AddStringToObject(gateway, "interface", gw_if);
        double rtt_ms = -1.0;
        const bool reachable = ping_host(gw_ip, &rtt_ms);
        cJSON_AddBoolToObject(gateway, "reachable", reachable);
        if (reachable && rtt_ms >= 0.0)
            cJSON_AddNumberToObject(gateway, "rtt_ms", round(rtt_ms * 100.0) / 100.0);
    } else {
        cJSON_AddStringToObject(gateway, "ip", "none");
        cJSON_AddBoolToObject(gateway, "reachable", false);
    }
    return gateway;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *usbdevs_build_json(void) {
    cJSON *arr = cJSON_CreateArray();
    DIR *d = opendir("/sys/bus/usb/devices");
    if (d) {
        struct dirent *ent;
        while ((ent = readdir(d)) != NULL) {
            // skip ourselves
            if (ent->d_name[0] == '.')
                continue;
            // skip interface entries (contain ':')
            if (strchr(ent->d_name, ':') != NULL)
                continue;
            // skip root hubs (usb1, usb2, etc.)
            if (strncmp(ent->d_name, "usb", 3) == 0)
                continue;
            char path[PATH_MAX], buf[128];
            if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/bus/usb/devices/%s/idVendor", ent->d_name), buf, sizeof(buf))) {
                cJSON *dev = cJSON_CreateObject();
                cJSON_AddStringToObject(dev, "bus_id", ent->d_name);
                cJSON_AddStringToObject(dev, "vendor_id", buf);
                if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/bus/usb/devices/%s/idProduct", ent->d_name), buf, sizeof(buf)))
                    cJSON_AddStringToObject(dev, "product_id", buf);
                if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/bus/usb/devices/%s/manufacturer", ent->d_name), buf, sizeof(buf)))
                    cJSON_AddStringToObject(dev, "manufacturer", buf);
                if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/bus/usb/devices/%s/product", ent->d_name), buf, sizeof(buf)))
                    cJSON_AddStringToObject(dev, "product", buf);
                if (read_file_string(snprintf_inline(path, sizeof(path), "/sys/bus/usb/devices/%s/serial", ent->d_name), buf, sizeof(buf)))
                    cJSON_AddStringToObject(dev, "serial", buf);
                cJSON_AddItemToArray(arr, dev);
            }
        }
        closedir(d);
    }
    return arr;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *mqtt_build_json(void) {
    cJSON *mqtt = cJSON_CreateObject();
    cJSON_AddBoolToObject(mqtt, "connected", mqtt_is_connected(&state.mqtt_ctx));
    cJSON_AddNumberToObject(mqtt, "connects", (double)state.mqtt_ctx.stat_connects);
    cJSON_AddNumberToObject(mqtt, "disconnects", (double)state.mqtt_ctx.stat_disconnects);
    cJSON_AddNumberToObject(mqtt, "reconnects", (double)state.mqtt_ctx.stat_reconnects);
    cJSON_AddNumberToObject(mqtt, "publishes", (double)state.mqtt_ctx.stat_publishes);
    cJSON_AddNumberToObject(mqtt, "publish_bytes", (double)state.mqtt_ctx.stat_publish_bytes);
    cJSON_AddNumberToObject(mqtt, "publish_errors", (double)state.mqtt_ctx.stat_publish_errors);
    if (state.mqtt_ctx.stat_last_connect_time > 0)
        cJSON_AddStringToObject(mqtt, "last_connect_time", strtime_iso8601(state.mqtt_ctx.stat_last_connect_time));
    if (last_publish_time > 0)
        cJSON_AddStringToObject(mqtt, "last_publish_time", strtime_iso8601(last_publish_time));
    return mqtt;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *build_system_json(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", strtime_iso8601(time(NULL)));
    cJSON_AddStringToObject(root, "type", "system");

    cJSON *sub;

    // show uptime
    struct sysinfo si;
    if (sysinfo(&si) == 0) {
        char uptime[64];
        cJSON_AddNumberToObject(root, "uptime_secs", (double)si.uptime);
        cJSON_AddStringToObject(root, "uptime", snprintf_inline(uptime, sizeof(uptime), "%dd %dh %dm", (int)(si.uptime / 86400), (int)((si.uptime % 86400) / 3600), (int)((si.uptime % 3600) / 60)));
    }

    // show load
    if ((sub = load_build_json()) != NULL)
        cJSON_AddItemToObject(root, "load", sub);

    // show memory
    if ((sub = memory_build_json()) != NULL)
        cJSON_AddItemToObject(root, "memory", sub);

    // show cpu temperature / frequency / throttling
    if ((sub = cpu_build_json()) != NULL)
        cJSON_AddItemToObject(root, "cpu", sub);

    // show network interfaces
    if ((sub = network_build_json()) != NULL)
        cJSON_AddItemToObject(root, "network", sub);

    // show mqtt connection status
    if ((sub = mqtt_build_json()) != NULL)
        cJSON_AddItemToObject(root, "mqtt", sub);

    // show disk usage (root filesystem)
    if ((sub = disk_build_json()) != NULL)
        cJSON_AddItemToObject(root, "disk", sub);

    // show eMMC/SD health
    if ((sub = mmc_health_build_json()) != NULL)
        cJSON_AddItemToObject(root, "mmc", sub);

    // show USB devices
    if ((sub = usbdevs_build_json()) != NULL)
        cJSON_AddItemToObject(root, "usb", sub);

    // check processes
    if (state.processes_count > 0 && (sub = processes_build_json()) != NULL)
        cJSON_AddItemToObject(root, "processes", sub);

    // check time synchronisation
    if (state.check_timesync && (sub = timesync_build_json()) != NULL)
        cJSON_AddItemToObject(root, "timesync", sub);

    // check gateway reachability
    if (state.check_gateway && (sub = gateway_build_json()) != NULL)
        cJSON_AddItemToObject(root, "gateway", sub);

    // check DNS resolver
    if (state.check_resolve && *state.check_resolve && (sub = resolve_build_json()) != NULL)
        cJSON_AddItemToObject(root, "resolve", sub);

    // check topics liveness
    if (state.check_topics.enabled && (sub = mqtttopics_build_json(&state.check_topics)) != NULL)
        cJSON_AddItemToObject(root, "topics", sub);

    return root;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

static cJSON *build_platform_json(void) {
    struct utsname uts;
    if (uname(&uts) != 0)
        return NULL;

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "timestamp", strtime_iso8601(time(NULL)));
    cJSON_AddStringToObject(root, "type", "platform");
    cJSON_AddStringToObject(root, "hostmon_version", HOSTMON_VERSION);

    cJSON_AddStringToObject(root, "hostname", uts.nodename);
    cJSON_AddStringToObject(root, "kernel", uts.release);
    cJSON_AddStringToObject(root, "kernel_version", uts.version);
    cJSON_AddStringToObject(root, "arch", uts.machine);
    cJSON_AddStringToObject(root, "os", uts.sysname);

    // os-release
    char buf[256];
    if (read_file_string("/etc/hostname", buf, sizeof(buf)))
        cJSON_AddStringToObject(root, "hostname_file", buf);
    FILE *f = fopen("/etc/os-release", "r");
    if (f) {
        char line[256];
        while (fgets(line, (int)sizeof(line), f))
#define _STR_PRETTY_NAME "PRETTY_NAME="
            if (strncmp(line, _STR_PRETTY_NAME, sizeof(_STR_PRETTY_NAME) - 1) == 0) {
                char *val = line + (sizeof(_STR_PRETTY_NAME) - 1);
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
    if (sysinfo(&si) == 0)
        cJSON_AddStringToObject(root, "boot_time", strtime_iso8601(time(NULL) - si.uptime));

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
    if (!json || !mqtt_is_connected(&state.mqtt_ctx))
        return false;
    char *str = cJSON_PrintUnformatted(json);
    if (!str) {
        cJSON_Delete(json);
        return false;
    }
    char topic[TOPIC_MAX], hostname[64];
    if (gethostname(hostname, sizeof(hostname)) != 0)
        snprintf(hostname, sizeof(hostname), "unknown");
    const bool ok = mqtt_send(&state.mqtt_ctx, snprintf_inline(topic, sizeof(topic), "%s/%s/%s", state.mqtt_topic_prefix, hostname, subtopic), str, (int)strlen(str));
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
           state.check_resolve ? state.check_resolve : "none", state.mqtt_topic_prefix);

    processes_init();
    interfaces_init();
    mqtttopics_init(&state.check_topics);

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
            mqtt_loop(&state.mqtt_ctx, 1000);
        else
            usleep(1000000); /* 1 second */
        mqtttopics_loop(&state.check_topics, 50);
    }

    mqtttopics_term(&state.check_topics);
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
    snprintf(state.mqtt_ctx.log_prefix, sizeof(state.mqtt_ctx.log_prefix), "mqtt");
    mqtt_config_populate(&state.mqtt_config);
    state.mqtt_topic_prefix = config_get_string("mqtt-topic-prefix", MQTT_TOPIC_PREFIX_DEFAULT);
    state.interval_platform = (time_t)config_get_integer("interval-platform", INTERVAL_PLATFORM_DEFAULT);
    state.interval_system = (time_t)config_get_integer("interval-system", INTERVAL_SYSTEM_DEFAULT);
    const char *processes_csv = config_get_string("check-processes", NULL);
    if (processes_csv)
        processes_parse(processes_csv);
    if (!interfaces_discover())
        printf("hostmon: WARNING no network interfaces discovered\n");
    state.check_timesync = config_get_bool("check-timesync", true);
    state.check_gateway = config_get_bool("check-gateway", true);
    state.check_resolve = config_get_string("check-resolve", NULL);
    const char *check_topics = config_get_string("check-topics", NULL);
    if (check_topics && *check_topics)
        mqtttopics_setup(&state.check_topics, check_topics, state.mqtt_config.client);
    state.debug = config_get_bool("debug", false);

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

    if (!mqtt_begin(&state.mqtt_ctx, &state.mqtt_config))
        return EXIT_FAILURE;

    hostmon_run();

    mqtt_end(&state.mqtt_ctx);

    return EXIT_SUCCESS;
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------
