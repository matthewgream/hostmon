
// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#ifndef MQTT_LINUX_H
#define MQTT_LINUX_H

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <mosquitto.h>

// -----------------------------------------------------------------------------------------------------------------------------------------

typedef struct {
    const char *server;
    const char *client;
    bool use_synchronous;
    bool tls_insecure;
    unsigned int reconnect_delay;
    unsigned int reconnect_delay_max;
    bool debug;
} mqtt_config_t;

typedef void (*mqtt_message_handler_t)(void *user_data, const char *topic, const unsigned char *payload, int payloadlen);
typedef void (*mqtt_connect_handler_t)(void *user_data, bool connected);

typedef struct {
    struct mosquitto *mosq;
    bool synchronous;
    bool connected;
    uint32_t stat_connects;
    uint32_t stat_disconnects;
    uint32_t stat_reconnects;
    time_t stat_last_connect_time;
    uint32_t stat_publishes;
    uint64_t stat_publish_bytes;
    uint32_t stat_publish_errors;
    mqtt_message_handler_t message_handler;
    mqtt_connect_handler_t connect_handler;
    void *handler_user_data;
    unsigned int reconnect_delay_base;
    unsigned int reconnect_delay_max_base;
    unsigned int reconnect_delay_current;
    time_t reconnect_next_attempt;
    char log_prefix[16];
} mqtt_context_t;

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtt_send(mqtt_context_t *ctx, const char *topic, const char *message, const int length) {
    if (!ctx->mosq || !ctx->connected) {
        ctx->stat_publish_errors++;
        return false;
    }
    const int result = mosquitto_publish(ctx->mosq, NULL, topic, length, message, MQTT_PUBLISH_QOS, MQTT_PUBLISH_RETAIN);
    if (result != MOSQ_ERR_SUCCESS) {
        ctx->stat_publish_errors++;
        fprintf(stderr, "%s: publish error: %s\n", ctx->log_prefix, mosquitto_strerror(result));
        return false;
    }
    ctx->stat_publishes++;
    ctx->stat_publish_bytes += (uint64_t)length;
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtt_message_callback_wrapper(struct mosquitto *m __attribute__((unused)), void *userdata, const struct mosquitto_message *message) {
    mqtt_context_t *ctx = (mqtt_context_t *)userdata;
    if (!ctx)
        return;
    if (ctx->message_handler)
        ctx->message_handler(ctx->handler_user_data, (const char *)message->topic, message->payload, message->payloadlen);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void mqtt_set_handlers(mqtt_context_t *ctx, mqtt_message_handler_t msg_cb, mqtt_connect_handler_t conn_cb, void *user_data) {
    ctx->message_handler = msg_cb;
    ctx->connect_handler = conn_cb;
    ctx->handler_user_data = user_data;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtt_subscribe(mqtt_context_t *ctx, const char *topic, const int qos) {
    if (!ctx->mosq)
        return false;
    const int result = mosquitto_subscribe(ctx->mosq, NULL, topic, qos);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "%s: subscribe error: %s\n", ctx->log_prefix, mosquitto_strerror(result));
        return false;
    }
    printf("%s: subscribed to topic '%s' (qos=%d)\n", ctx->log_prefix, topic, qos);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

__attribute__((unused)) static bool mqtt_unsubscribe(mqtt_context_t *ctx, const char *topic) {
    if (!ctx->mosq)
        return false;
    const int result = mosquitto_unsubscribe(ctx->mosq, NULL, topic);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "%s: unsubscribe error: %s\n", ctx->log_prefix, mosquitto_strerror(result));
        return false;
    }
    printf("%s: unsubscribed from topic '%s'\n", ctx->log_prefix, topic);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool __mqtt_parse(const char *string, char *host, const int length, int *port, bool *ssl) {
    host[0] = '\0';
    *port = 1883;
    *ssl = false;
    if (strncmp(string, "mqtt://", 7) == 0)
        strncpy(host, string + 7, (size_t)length - 1);
    else if (strncmp(string, "mqtts://", 8) == 0) {
        strncpy(host, string + 8, (size_t)length - 1);
        *ssl = true;
        *port = 8883;
    } else
        strncpy(host, string, (size_t)length - 1);
    char *port_str = strchr(host, ':');
    if (port_str) {
        *port_str = '\0'; // Terminate host string at colon
        *port = atoi(port_str + 1);
    }
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtt_connect_callback(struct mosquitto *m __attribute__((unused)), void *userdata, int r) {
    mqtt_context_t *ctx = (mqtt_context_t *)userdata;
    if (!ctx)
        return;
    if (r != 0) {
        fprintf(stderr, "%s: connect failed: %s\n", ctx->log_prefix, mosquitto_connack_string(r));
        return;
    }
    ctx->connected = true;
    ctx->stat_connects++;
    ctx->stat_last_connect_time = time(NULL);
    ctx->reconnect_delay_current = ctx->reconnect_delay_base;
    ctx->reconnect_next_attempt = 0;
    printf("%s: connected\n", ctx->log_prefix);
    if (ctx->connect_handler)
        ctx->connect_handler(ctx->handler_user_data, true);
}

static void __mqtt_disconnect_callback(struct mosquitto *m __attribute__((unused)), void *userdata, int r) {
    mqtt_context_t *ctx = (mqtt_context_t *)userdata;
    if (!ctx)
        return;
    ctx->connected = false;
    ctx->stat_disconnects++;
    if (r == 0)
        printf("%s: disconnected (clean)\n", ctx->log_prefix);
    else
        fprintf(stderr, "%s: disconnected unexpectedly: rc=%d\n", ctx->log_prefix, r);
    if (ctx->connect_handler)
        ctx->connect_handler(ctx->handler_user_data, false);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtt_reconnect_attempt(mqtt_context_t *ctx) {
    const time_t now = time(NULL);
    if (now < ctx->reconnect_next_attempt)
        return;
    if (ctx->reconnect_delay_current == 0)
        ctx->reconnect_delay_current = ctx->reconnect_delay_base ? ctx->reconnect_delay_base : 1;
    printf("%s: attempting reconnect\n", ctx->log_prefix);
    const int r = mosquitto_reconnect(ctx->mosq);
    if (r == MOSQ_ERR_SUCCESS) {
        ctx->stat_reconnects++;
        ctx->reconnect_delay_current = ctx->reconnect_delay_base;
        ctx->reconnect_next_attempt = 0;
    } else {
        fprintf(stderr, "%s: reconnect failed: %s (next attempt in %us)\n", ctx->log_prefix, mosquitto_strerror(r), ctx->reconnect_delay_current);
        ctx->reconnect_next_attempt = now + (time_t)ctx->reconnect_delay_current;
        ctx->reconnect_delay_current *= 2;
        if (ctx->reconnect_delay_max_base > 0 && ctx->reconnect_delay_current > ctx->reconnect_delay_max_base)
            ctx->reconnect_delay_current = ctx->reconnect_delay_max_base;
    }
}

static void mqtt_loop(mqtt_context_t *ctx, const int timeout_ms) {
    if (!ctx->mosq)
        return;
    const int rc = mosquitto_loop(ctx->mosq, timeout_ms, 1);
    if (rc != MOSQ_ERR_SUCCESS) {
        if (ctx->connected) {
            ctx->connected = false;
            ctx->stat_disconnects++;
            fprintf(stderr, "%s: loop error: %s\n", ctx->log_prefix, mosquitto_strerror(rc));
            if (ctx->connect_handler)
                ctx->connect_handler(ctx->handler_user_data, false);
        }
        __mqtt_reconnect_attempt(ctx);
    }
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtt_begin(mqtt_context_t *ctx, const mqtt_config_t *cfg) {
    char host[256];
    int port;
    bool ssl;
    if (!__mqtt_parse(cfg->server, host, sizeof(host), &port, &ssl)) {
        fprintf(stderr, "%s: error parsing details in '%s'\n", ctx->log_prefix, cfg->server);
        return false;
    }
    if (ctx->log_prefix[0] == '\0')
        snprintf(ctx->log_prefix, sizeof(ctx->log_prefix), "mqtt");
    printf("%s: connecting (host='%s', port=%d, ssl=%s, client='%s')\n", ctx->log_prefix, host, port, ssl ? "true" : "false", cfg->client);
    char client_id[24];
    snprintf(client_id, sizeof(client_id), "%s-%06X", cfg->client ? cfg->client : "mqtt-linux", (unsigned int)(time(NULL) ^ getpid()) & 0xFFFFFF);
    mosquitto_lib_init();
    ctx->mosq = mosquitto_new(client_id, true, ctx);
    if (!ctx->mosq) {
        fprintf(stderr, "%s: error creating client instance\n", ctx->log_prefix);
        return false;
    }
    if (ssl) {
        mosquitto_tls_set(ctx->mosq, NULL, NULL, NULL, NULL, NULL);
        if (cfg->tls_insecure) {
            mosquitto_tls_insecure_set(ctx->mosq, true);
            printf("%s: WARNING tls certificate validation disabled\n", ctx->log_prefix);
        }
    }
    mosquitto_connect_callback_set(ctx->mosq, __mqtt_connect_callback);
    mosquitto_disconnect_callback_set(ctx->mosq, __mqtt_disconnect_callback);
    mosquitto_message_callback_set(ctx->mosq, __mqtt_message_callback_wrapper);
    if (cfg->reconnect_delay > 0)
        mosquitto_reconnect_delay_set(ctx->mosq, cfg->reconnect_delay, cfg->reconnect_delay_max, true);
    ctx->reconnect_delay_base = cfg->reconnect_delay > 0 ? cfg->reconnect_delay : 1;
    ctx->reconnect_delay_max_base = cfg->reconnect_delay_max > 0 ? cfg->reconnect_delay_max : ctx->reconnect_delay_base;
    ctx->reconnect_delay_current = ctx->reconnect_delay_base;
    ctx->reconnect_next_attempt = 0;
    int result;
    if ((result = mosquitto_connect(ctx->mosq, host, port, MQTT_CONNECT_TIMEOUT)) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "%s: error connecting to broker: %s\n", ctx->log_prefix, mosquitto_strerror(result));
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
        return false;
    }
    ctx->synchronous = cfg->use_synchronous;
    if (!ctx->synchronous && (result = mosquitto_loop_start(ctx->mosq)) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "%s: error starting loop: %s\n", ctx->log_prefix, mosquitto_strerror(result));
        mosquitto_disconnect(ctx->mosq);
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
        return false;
    }
    if (ctx->synchronous)
        for (int i = 0; i < 50 && !ctx->connected; i++)
            mosquitto_loop(ctx->mosq, 100, 1);

    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static bool mqtt_is_connected(const mqtt_context_t *ctx) {
    return ctx && ctx->mosq && ctx->connected;
}

static void mqtt_end(mqtt_context_t *ctx) {
    ctx->connected = false;
    if (ctx->mosq) {
        if (!ctx->synchronous)
            mosquitto_loop_stop(ctx->mosq, true);
        mosquitto_disconnect(ctx->mosq);
        mosquitto_destroy(ctx->mosq);
        ctx->mosq = NULL;
    }
    mosquitto_lib_cleanup();
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

#endif /* MQTT_LINUX_H */
