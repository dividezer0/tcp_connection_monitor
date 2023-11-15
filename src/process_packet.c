#include "tcp_monitor.h"

#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/ethernet.h>

typedef enum _tcp_connection_phases_t {
	TCP_PHASE_CONNECTION_REQUEST = 0,
	TCP_PHASE_CONNECTION_REPLY = 1,
	TCP_PHASE_CONNECTION_SUCCESS = 2,
} tcp_connection_phases_t;

static void tcp_connection_report(const char *format,  ...) {
	va_list args;

	va_start(args, format);
	if (output_file && output_file != stdout) {
		vfprintf(output_file, format, args);
	} 

	if (print_to_stdout) {
		vfprintf(stdout, format, args);
	}
	
	fflush(output_file);

	va_end(args);
}


guint connection_data_hash(const void *arg)
{
	tcp_connection_key_t *key;

	assert(arg);

	key = (tcp_connection_key_t *) arg;
	guint res = g_int_hash(&key->ip1);
	res |= g_int_hash(&key->ip2);
	res |= g_int_hash(&key->port1);
	res |= g_int_hash(&key->port2);
	return res;
}

gboolean connection_data_equal(const void *first_arg, const void *second_arg)
{
	tcp_connection_key_t *first,  *second;

	assert(first_arg);
	assert(second_arg);

	first = (tcp_connection_key_t *)first_arg;
	second = (tcp_connection_key_t *)second_arg;

	if ((first->ip1 == second->ip1) && (first->ip2 == second->ip2) && (first->port1 == second->port1) &&
			(first->port2 == second->port2)) {
		return TRUE;	
	}

	return FALSE;
}

guint failed_connection_data_hash(const void *arg)
{
	tcp_failed_connection_key_t *key;

	assert(arg);

	key = (tcp_failed_connection_key_t *)arg;

	guint res = g_int_hash(&key->ip1);
	res |= g_int_hash(&key->ip2);
	res |= g_int_hash(&key->port2);
	return res;
}

gboolean failed_connection_data_equal(const void *first_arg, const void *second_arg)
{
	tcp_failed_connection_key_t *first,  *second;

	assert(first_arg);
	assert(second_arg);

	first = (tcp_failed_connection_key_t *)first_arg;
	second = (tcp_failed_connection_key_t *)second_arg;

	if ((first->ip1 == second->ip1) && (first->ip2 == second->ip2) && (first->port2 == second->port2)) {
		return TRUE;	
	}

	return FALSE;
}

static uint32_t get_failed_connection_counter(
	tcp_connection_counter_ctx_t *ctx,
	tcp_connection_key_t *connection,
	uint32_t *failed_counter
)
{
	tcp_failed_connection_key_t *failed_connection_ptr;
	uint32_t *failed_counter_ptr;
	int ret = 0;

	failed_connection_ptr = g_malloc(sizeof(*failed_connection_ptr));
	if (!failed_connection_ptr) {
		TCP_CONNECTION_LOG("Failed to allocate memory for failed connection\n");
		ret = 1;
		goto out;
	}

	failed_connection_ptr->ip1 = connection->ip1;
	failed_connection_ptr->ip2 = connection->ip2;
	failed_connection_ptr->port2 = connection->port2;
	failed_counter_ptr = g_hash_table_lookup(ctx->failed_connection_data, failed_connection_ptr);

	if (failed_counter_ptr) {
		(*failed_counter_ptr)++;
		g_free(failed_connection_ptr);
	} else {
		failed_counter_ptr = g_malloc(sizeof(*failed_counter_ptr));
		if (!failed_counter_ptr) {
			TCP_CONNECTION_LOG("Failed to allocate memory for failed connection counter\n");
			ret = 1;
			goto out;
		}

		*failed_counter_ptr = 1;
		g_hash_table_insert(ctx->failed_connection_data, failed_connection_ptr, failed_counter_ptr);
	}

	*failed_counter = *failed_counter_ptr;
out:
	if (ret) {
		if (failed_connection_ptr) {
			g_free(failed_connection_ptr);
		}
		if (failed_counter_ptr) {
			g_free(failed_counter_ptr);
		}
	} 

	return ret;
}

static int process_stored_connection(
	tcp_connection_counter_ctx_t *ctx,
	tcp_connection_phases_t phase_packet,
	tcp_connection_key_t *connection,
	tcp_connection_phases_t *phase_stored
	)
{
	uint32_t failed_counter;
	int connection_failed = 0;
	int connection_success = 0;
	int err = 0;
	char ip_src[INET_ADDRSTRLEN], ip_dst[INET_ADDRSTRLEN];
	uint16_t port_src, port_dst;

	assert(ctx);
	assert(connection);
	assert(phase_stored);

	if (phase_packet == TCP_PHASE_CONNECTION_REQUEST) {
		if ((*phase_stored == TCP_PHASE_CONNECTION_REQUEST) || (*phase_stored == TCP_PHASE_CONNECTION_REPLY)) {
			connection_failed = 1;			
		} else if (*phase_stored == TCP_PHASE_CONNECTION_SUCCESS) {
			//assume second connection
			*phase_stored = TCP_PHASE_CONNECTION_REQUEST;
		}
	} else if (phase_packet == TCP_PHASE_CONNECTION_REPLY) {
		if ((*phase_stored == TCP_PHASE_CONNECTION_REPLY) || (*phase_stored == TCP_PHASE_CONNECTION_SUCCESS)) {
			connection_failed = 1;
		} else if (*phase_stored == TCP_PHASE_CONNECTION_REQUEST) {
			*phase_stored = TCP_PHASE_CONNECTION_REPLY;
		}
	} else if (phase_packet == TCP_PHASE_CONNECTION_SUCCESS) {
		if (*phase_stored == TCP_PHASE_CONNECTION_REPLY) {
			*phase_stored = TCP_PHASE_CONNECTION_SUCCESS;
			connection_success = 1;
		} else if (*phase_stored == TCP_PHASE_CONNECTION_REQUEST) {
			connection_failed = 1;
		}
	}
	
	if (connection_failed || connection_success) {
		inet_ntop(AF_INET, &connection->ip1, ip_src, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &connection->ip2, ip_dst, INET_ADDRSTRLEN);
		port_src = ntohs(connection->port1);
		port_dst = ntohs(connection->port2);
	}

	if (connection_failed) {
		err = get_failed_connection_counter(ctx, connection, &failed_counter);
		if (err) {
			TCP_CONNECTION_LOG("Failed to get failed connection counter\n");
			goto out;
		}

		tcp_connection_report(FAILED_CONNECTION_STR, ip_src, port_src, ip_dst, port_dst, failed_counter);

		g_hash_table_remove(ctx->connection_data, connection);
	} else if (connection_success) {
		tcp_connection_report(SUCCESS_CONNECTION_STR, ip_src, port_src, ip_dst, port_dst);
	}
	
out:
	return err;
}

int process_packet(tcp_connection_counter_ctx_t *ctx, const uint8_t *packet)
{
	struct iphdr *ip_header;
	struct tcphdr *tcp_header;
	tcp_connection_key_t *connection, *connection_orig;
	tcp_connection_phases_t *phase_stored;
	tcp_connection_phases_t phase_packet;
	gboolean found;
	int err = 0;
	int is_syn, is_ack;
	
	assert(ctx);

	//TODO implement
	// if (ctx->is_interface_wifi) {
	// 	packet += WIFI_HEADER_LENGTH;
	// } else {
		packet += sizeof(struct ether_header);
	// }

	ip_header = (struct iphdr *)packet;

	packet += sizeof(*ip_header);
	tcp_header = (struct tcphdr *)packet;

	is_ack = !!(tcp_header->th_flags & TH_ACK);
	is_syn = !!(tcp_header->th_flags & TH_SYN);

	connection = g_malloc(sizeof(*connection));
	if (!connection) {
		TCP_CONNECTION_LOG("Failed to allocate memory for tcp connection data\n");
		err = 1;
	}

	if (is_syn != is_ack) {
		connection->ip1 = ip_header->saddr;
		connection->ip2 = ip_header->daddr;
		connection->port1 = tcp_header->th_sport;
		connection->port2 = tcp_header->th_dport;
	} else {
		connection->ip1 = ip_header->daddr;
		connection->ip2 = ip_header->saddr;
		connection->port1 = tcp_header->th_dport;
		connection->port2 = tcp_header->th_sport;
	}

	if (is_syn && (!is_ack)) {
		phase_packet = TCP_PHASE_CONNECTION_REQUEST;
	} else if (is_syn && is_ack) {
		phase_packet = TCP_PHASE_CONNECTION_REPLY;
	} else {
		phase_packet = TCP_PHASE_CONNECTION_SUCCESS;
	}

	found = g_hash_table_lookup_extended(ctx->connection_data, connection, (gpointer*)&connection_orig, (gpointer*)&phase_stored);
	if (found) {
		err = process_stored_connection(ctx, phase_packet, connection_orig, phase_stored);
		if (err) {
			TCP_CONNECTION_LOG("Failed to process stored connection\n");
			goto out;
		}
	} else if ((phase_packet == TCP_PHASE_CONNECTION_REQUEST) || (phase_packet == TCP_PHASE_CONNECTION_SUCCESS)) {
		phase_stored = g_malloc(sizeof(*phase_stored));
		if (!phase_stored) {
			TCP_CONNECTION_LOG("Failed to allocate memort for new connection\n");
			err = 1;
			goto out;
		}

		*phase_stored = phase_packet;
		g_hash_table_insert(ctx->connection_data, connection, phase_stored);
	} 

out:
	if (err) {
		if (connection) {
			g_free(connection);
		}
		if (!found && phase_stored) {
			g_free(phase_stored);
		}
	}

	return err;
}
