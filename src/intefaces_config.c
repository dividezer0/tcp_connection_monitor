#include "tcp_monitor.h"

void *run_pcap_thread_cb(tcp_connection_counter_interface_ctx_t *ctx)
{
	assert(ctx);

	ctx->thread_retval = run_pcap(ctx);

	return &ctx->thread_retval;
}

void interface_ctx_free(tcp_connection_counter_interface_ctx_t *ctx) {	
	if (ctx->connection_data) {
		g_hash_table_destroy(ctx->connection_data);
	}

	if (ctx->failed_connection_data) {
		g_hash_table_destroy(ctx->failed_connection_data);
	}

	clean_pcup(ctx);

	ctx->interface_name = NULL;
}

int configure_interface_ctx(char *interface_name, tcp_connection_counter_interface_ctx_t *ctx) 
{
	int err = 0;

	assert(interface_name);
	assert(ctx);

	ctx->interface_name = interface_name;
	err = configure_pcap(ctx);
	if (err) {
		TCP_CONNECTION_LOG("Failed to configure pcap interface\n");
		goto out;
	}

	ctx->connection_data = g_hash_table_new_full(connection_data_hash, connection_data_equal, g_free, g_free);
	if (!ctx->connection_data) {
		TCP_CONNECTION_LOG("Failed to alloc connection hash table for interface %s\n", ctx->interface_name);
		err = 1;
		goto out;
	}

	ctx->failed_connection_data = g_hash_table_new_full(failed_connection_data_hash, failed_connection_data_equal, g_free, g_free);
	if (!ctx->failed_connection_data) {
		TCP_CONNECTION_LOG("Failed to alloc failed connection hash table for interface %s\n", ctx->interface_name);
		err = 1;
		goto out;
	}

out:
	if (err) {
		interface_ctx_free(ctx);
	}

	return err;
}

void init_thread(gpointer key, gpointer value, tcp_connection_counter_ctx_t *ctx)
{
	assert(ctx);

	tcp_connection_counter_interface_ctx_t *interface;
	int err = 0;

	for (int i = 0; i < ctx->interfaces_count; i++) {
		if (!ctx->interfaces_data[i].interface_name) {
			interface = &ctx->interfaces_data[i];
			break;
		}
	}

	err = configure_interface_ctx(key, interface);
	if (err) {
		TCP_CONNECTION_LOG("Tcp monitor thread on interface %s failed with error\n", interface->interface_name);
		goto out;
	}

	err = pthread_create(&interface->thread_id, NULL, run_pcap_thread_cb, interface);
	if (err) {
		TCP_CONNECTION_LOG("Failed to create thread on interface %s\n", interface->interface_name);
		goto out;
	}

out:
	if (err) {
		keep_running = 0;

		interface_ctx_free(interface);
	}
}