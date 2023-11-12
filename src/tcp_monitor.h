#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

#include <pthread.h>
#include <glib.h>
#include <pcap.h>
#include <stdio.h>
#include <assert.h>

#define TCP_FILTER "ip and tcp[tcpflags] & (tcp-syn|tcp-ack) != 0 "
#define PROMISCOUS (1)
#define NONPROMISCOUS (0)
#define SNAP_LEN (65535)
#define TO_MS_MILISECONDS (200)

#define WIFI_HEADER_LENGTH (24)

#define SUCCESS_CONNECTION_STR "SUCCESS %s:%d -> %s:%d\n"
#define FAILED_CONNECTION_STR "FAILED %s:%d -> %s:%d COUNT %d\n"

#define TCP_CONNECTION_LOG(fmt, ...) do { \
	if (is_multithread) pthread_mutex_lock(&log_lock);\
	fprintf(log_file, "%s:%d: " fmt, __FUNCTION__, __LINE__,##__VA_ARGS__); \
	fflush(log_file); \
	if (is_multithread) pthread_mutex_unlock(&log_lock);\
} while(0)

extern volatile int keep_running;
extern FILE *log_file;
extern FILE *output_file;
extern int print_to_stdout;

extern int is_multithread;
extern pthread_mutex_t log_lock;
extern pthread_mutex_t output_lock;

typedef struct _tcp_connection_counter_interface_ctx_t {
	pthread_t thread_id;
	int thread_retval;
	GHashTable *connection_data;
	GHashTable *failed_connection_data;
	char *interface_name;
	int is_interface_wifi;
	pcap_t *handle;
	struct bpf_program compiled_filter_expr;
} tcp_connection_counter_interface_ctx_t;

typedef struct _tcp_connection_counter_ctx_t {
	char *output_filename;
	char *log_filename;
	GHashTable *interfaces;
	int all_interfaces;
	char *interface_name;
	struct ifaddrs *addrs;
	tcp_connection_counter_interface_ctx_t *interfaces_data;
	uint32_t interfaces_count;
} tcp_connection_counter_ctx_t;

typedef struct _tcp_connection_key_t{
	uint32_t ip1;
	uint32_t ip2;
	uint32_t port1;
	uint32_t port2; 
} tcp_connection_key_t;

typedef struct _tcp_failed_connection_val_t{
	uint32_t ip1;
	uint32_t ip2;
	uint32_t port2; 
} tcp_failed_connection_key_t;

guint connection_data_hash(tcp_connection_key_t *key);
gboolean connection_data_equal(tcp_connection_key_t *first, tcp_connection_key_t *second);
guint failed_connection_data_hash(tcp_failed_connection_key_t *key);
gboolean failed_connection_data_equal(tcp_failed_connection_key_t *first, tcp_failed_connection_key_t *second);
int process_packet(tcp_connection_counter_interface_ctx_t *ctx, const uint8_t *packet);

int run_pcap(tcp_connection_counter_interface_ctx_t *ctx);
void clean_pcup(tcp_connection_counter_interface_ctx_t *ctx);
int configure_pcap(tcp_connection_counter_interface_ctx_t *interface_ctx);

void *run_pcap_thread_cb(tcp_connection_counter_interface_ctx_t *ctx);
void interface_ctx_free(tcp_connection_counter_interface_ctx_t *ctx);
int configure_interface_ctx(char *interface_name, tcp_connection_counter_interface_ctx_t *ctx);
void init_thread(gpointer key, gpointer value, tcp_connection_counter_ctx_t *ctx);

#endif //__TCP_MONITOR_H
