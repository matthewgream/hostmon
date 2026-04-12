
// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------

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
} mqtt_config_t;

// -----------------------------------------------------------------------------------------------------------------------------------------

struct mosquitto *mosq = NULL;
void (*mqtt_message_callback)(const char *, const unsigned char *, const int) = NULL;
bool mqtt_synchronous = false;
bool mqtt_connected = false;
uint32_t mqtt_stat_disconnects = 0;

// -----------------------------------------------------------------------------------------------------------------------------------------

bool mqtt_send(const char *topic, const char *message, const int length) {
    if (!mosq)
        return false;
    const int result = mosquitto_publish(mosq, NULL, topic, length, message, MQTT_PUBLISH_QOS, MQTT_PUBLISH_RETAIN);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: publish error: %s\n", mosquitto_strerror(result));
        return false;
    }
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

static void __mqtt_message_callback_wrapper(struct mosquitto *m, void *o __attribute__((unused)), const struct mosquitto_message *message) {
    if (m != mosq)
        return;
    if (mqtt_message_callback)
        mqtt_message_callback((const char *)message->topic, message->payload, message->payloadlen);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

bool mqtt_subscribe(const char *topic, const int qos, void (*callback)(const char *, const unsigned char *, const int)) {
    if (!mosq)
        return false;
    mqtt_message_callback = callback;
    const int result = mosquitto_subscribe(mosq, NULL, topic, qos);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: subscribe error: %s\n", mosquitto_strerror(result));
        return false;
    }
    printf("mqtt: subscribed to topic '%s' (qos=%d)\n", topic, qos);
    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

bool mqtt_unsubscribe(const char *topic) {
    if (!mosq)
        return false;
    const int result = mosquitto_unsubscribe(mosq, NULL, topic);
    if (result != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: unsubscribe error: %s\n", mosquitto_strerror(result));
        return false;
    }
    printf("mqtt: unsubscribed from topic '%s'\n", topic);
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

static void __mqtt_connect_callback(struct mosquitto *m, void *o __attribute__((unused)), int r) {
    if (m != mosq)
        return;
    if (r != 0) {
        fprintf(stderr, "mqtt: connect failed: %s\n", mosquitto_connack_string(r));
        return;
    }
    mqtt_connected = true;
    printf("mqtt: connected\n");
}

static void __mqtt_disconnect_callback(struct mosquitto *m, void *o __attribute__((unused)), int r) {
    if (m != mosq)
        return;
    mqtt_connected = false;
    mqtt_stat_disconnects++;
    if (r == 0)
        printf("mqtt: disconnected (clean)\n");
    else
        fprintf(stderr, "mqtt: disconnected unexpectedly: rc=%d\n", r);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

void mqtt_loop(const int timeout_ms) {
    if (mosq)
        mosquitto_loop(mosq, timeout_ms, 1);
}

// -----------------------------------------------------------------------------------------------------------------------------------------

bool mqtt_begin(const mqtt_config_t *cfg) {
    char host[256];
    int port;
    bool ssl;
    if (!__mqtt_parse(cfg->server, host, sizeof(host), &port, &ssl)) {
        fprintf(stderr, "mqtt: error parsing details in '%s'\n", cfg->server);
        return false;
    }
    printf("mqtt: connecting (host='%s', port=%d, ssl=%s, client='%s')\n", host, port, ssl ? "true" : "false", cfg->client);
    char client_id[24];
    snprintf(client_id, sizeof(client_id), "%s-%06X", cfg->client ? cfg->client : "mqtt-linux", (unsigned int)(time(NULL) ^ getpid()) & 0xFFFFFF);
    mosquitto_lib_init();
    mosq = mosquitto_new(client_id, true, NULL);
    if (!mosq) {
        fprintf(stderr, "mqtt: error creating client instance\n");
        return false;
    }
    if (ssl) {
        mosquitto_tls_set(mosq, NULL, NULL, NULL, NULL, NULL);
        if (cfg->tls_insecure) {
            mosquitto_tls_insecure_set(mosq, true);
            printf("mqtt: WARNING tls certificate validation disabled\n");
        }
    }
    mosquitto_connect_callback_set(mosq, __mqtt_connect_callback);
    mosquitto_disconnect_callback_set(mosq, __mqtt_disconnect_callback);
    mosquitto_message_callback_set(mosq, __mqtt_message_callback_wrapper);
    if (cfg->reconnect_delay > 0)
        mosquitto_reconnect_delay_set(mosq, cfg->reconnect_delay, cfg->reconnect_delay_max, true);
    int result;
    if ((result = mosquitto_connect(mosq, host, port, MQTT_CONNECT_TIMEOUT)) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: error connecting to broker: %s\n", mosquitto_strerror(result));
        mosquitto_destroy(mosq);
        mosq = NULL;
        return false;
    }
    mqtt_synchronous = cfg->use_synchronous;
    if (!mqtt_synchronous && (result = mosquitto_loop_start(mosq)) != MOSQ_ERR_SUCCESS) {
        fprintf(stderr, "mqtt: error starting loop: %s\n", mosquitto_strerror(result));
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosq = NULL;
        return false;
    }

    return true;
}

// -----------------------------------------------------------------------------------------------------------------------------------------

bool mqtt_is_connected(void) {
    return mqtt_connected;
}

void mqtt_end(void) {
    mqtt_connected = false;
    if (mosq) {
        if (!mqtt_synchronous)
            mosquitto_loop_stop(mosq, true);
        mosquitto_disconnect(mosq);
        mosquitto_destroy(mosq);
        mosq = NULL;
    }
    mosquitto_lib_cleanup();
}

// -----------------------------------------------------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------------------------------------------------
