#ifndef __TCP_MONITOR_H
#define __TCP_MONITOR_H

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

#define SUCCESS_CONNECTION_STR "SUCCESS %s:%d -> %s:%d\n" //ip_src, port_src -> ip_dst, port_dst
#define FAILED_CONNECTION_STR "FAILED %s:%d -> %s:%d COUNT %d\n" //ip_src, port_src -> ip_dst, port_dst, failed_count

#define TCP_CONNECTION_LOG(fmt, ...) do { \
	fprintf(log_file, "%s:%d: " fmt, __FUNCTION__, __LINE__,##__VA_ARGS__); \
	fflush(log_file); \
} while(0)

extern volatile int keep_running;
extern FILE *log_file;
extern FILE *output_file;
extern int print_to_stdout;

typedef struct _tcp_connection_counter_interface_ctx_t {
	char *interface_name;
	pcap_t *handle;
	struct bpf_program compiled_filter_expr;
	int fd;
} tcp_connection_counter_interface_ctx_t;

typedef struct _tcp_connection_counter_ctx_t {
	char *output_filename;
	char *log_filename;
	char **interface_names;
	int all_interfaces;
	char *interface_name_from_cmd;
	struct ifaddrs *addrs;
	tcp_connection_counter_interface_ctx_t *interfaces_data;
	uint32_t interfaces_count;
	GHashTable *connection_data;
	GHashTable *failed_connection_data;
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

guint connection_data_hash(const void *arg);
gboolean connection_data_equal(const void *first_arg, const void *second_arg);
guint failed_connection_data_hash(const void *arg);
gboolean failed_connection_data_equal(const void *first_arg, const void *second_arg);
int process_packet(tcp_connection_counter_ctx_t *ctx, const uint8_t *packet);

int run_pcap(tcp_connection_counter_ctx_t *ctx);
void clean_pcup(tcp_connection_counter_interface_ctx_t *ctx);
int configure_pcap(tcp_connection_counter_interface_ctx_t *interface_ctx);

#endif //__TCP_MONITOR_H
