#include "tcp_monitor.h"

#include <getopt.h>
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>

#include <linux/if.h>
#include <arpa/inet.h>
#include <ifaddrs.h>

#include <signal.h>

volatile int keep_running = 1;
FILE *log_file;
FILE *output_file;
int print_to_stdout;

static tcp_connection_counter_ctx_t *context = NULL;

static void  int_signal_handler(int dummy) {
	keep_running = 0;

    if (context) {
        for (int i = 0; i < context->interfaces_count; i++) {
            if (context->interfaces_data[i].handle) {
                pcap_breakloop(context->interfaces_data[i].handle);
            }
        }
    }
}

static void read_options(int argc, char**argv, tcp_connection_counter_ctx_t *ctx, int *is_help)
{
	int option, interface_found = 0;
	assert(argc > 0);
	assert(argv);
	assert(ctx);
	assert(is_help);

	*is_help = 0;

	while ((option = getopt (argc, argv, "i:so:l:h")) != -1)
	{
		switch (option)
		{
		case 'i':
			if (!strcmp(optarg, "ALL")) {
				ctx->all_interfaces = 1;
			} else {
				ctx->interface_name_from_cmd = optarg;
			}
			interface_found = 1;

			break;
		case 'o':
			ctx->output_filename = optarg;
			break;
		case 's':
			print_to_stdout = 1;
			break;
		case 'l':
			ctx->log_filename = optarg;
			break;

		case '?':
		case 'h':
		default:
			*is_help = 1;
		}
	}

	if (!interface_found) {
		*is_help = 1;
		fprintf(stdout, "Interface is required\n");
	}

	if ((!ctx->output_filename) && (!print_to_stdout)) {
		*is_help = 1;
		fprintf(stdout, "Either [-o output_file] or [-s] for stdout must be chosen\n");
	}

	if (*is_help ) {
		fprintf(stdout, "Usage %s: <-i interface|ALL> <-t interface_type(wifi/eth)> [-s] [-o output_file] [-l log_file==stderr] [-h help]\n", argv[0]);
	}
}

static int configure_files(tcp_connection_counter_ctx_t *ctx) 
{
	int ret = 0;

	assert(ctx);

	if (ctx->output_filename) {
		output_file = fopen(ctx->output_filename, "w+");
		if (!output_file){ 
			ret = 1;
			TCP_CONNECTION_LOG("Failed to open output file %s: %s\n", ctx->output_filename, strerror(errno));
			goto out;
		}
	}

	if (ctx->log_filename == NULL) {
		log_file = stderr;
	} else {
		log_file = fopen(ctx->log_filename, "w+");
		if (!log_file) {
			log_file = stderr; 
			ret = 1;
			TCP_CONNECTION_LOG("Failed to open log file %s: %s\n", ctx->log_filename, strerror(errno));
			goto out;
		}
	}

out:
	if (ret) {
		if (ctx->output_filename && (output_file)) {
			fclose(output_file);
			output_file = NULL;
		}
	}

	return ret;
}

static void clean_files(tcp_connection_counter_ctx_t *ctx)
{
	assert(ctx);

	if (output_file) {
		fclose(output_file);
	}

	if (log_file && (log_file != stderr)) {
		fclose(log_file);
	}
}

static void free_interfaces_names_set(tcp_connection_counter_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->interface_names) {
		free(ctx->interface_names);
		ctx->interface_names = NULL;
	}

	if (ctx->addrs) {
		freeifaddrs(ctx->addrs);
		ctx->addrs = NULL;
	}

	ctx->interfaces_count = 0;
}

static int configure_interfaces_names_set(tcp_connection_counter_ctx_t *ctx)
{
	int err;
	GHashTable *interfaces_names_set;
	
	assert(ctx);

	if (ctx->all_interfaces) {

		err = getifaddrs(&ctx->addrs);
		if (err) {
			TCP_CONNECTION_LOG("Failed to get interface addresses: %s", strerror(errno));
			goto out;
		}

		interfaces_names_set = g_hash_table_new(g_str_hash, g_str_equal);
		if (!interfaces_names_set) {
			TCP_CONNECTION_LOG("Failed to allocate interfaces list\n");
			err = 1;
			goto out;
		}

		for (struct ifaddrs *addr = ctx->addrs; addr != NULL; addr = addr->ifa_next) {
			if ((strcmp("lo", addr->ifa_name) == 0) || !(addr->ifa_flags & (IFF_RUNNING))) {
				continue;
			}
			if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
				g_hash_table_add(interfaces_names_set, addr->ifa_name);
			}
		}
		ctx->interface_names =(char **) g_hash_table_get_keys_as_array(interfaces_names_set, (guint *) &ctx->interfaces_count);
		g_hash_table_destroy(interfaces_names_set);
	} else {
		ctx->interface_names = malloc(sizeof(*ctx->interface_names));
		if (!ctx->interface_names) {
			TCP_CONNECTION_LOG("Failed to allocate interfaces names array\n");
			err = 1;
			goto out;
		}

		ctx->interface_names[0] = ctx->interface_name_from_cmd;
		ctx->interfaces_count = 1;
	}

out:
	if (err) {
		if (interfaces_names_set) {
			g_hash_table_destroy(interfaces_names_set);
		}

		free_interfaces_names_set(ctx);
	}

	return err;
}

static void clean_global_context(tcp_connection_counter_ctx_t *ctx)
{
	assert(ctx);

	if (ctx->interface_names) {
		g_free(ctx->interface_names);
	}

	if (ctx->addrs) {
		freeifaddrs(ctx->addrs);
	}

	clean_files(ctx);
}

static int configure_global_context(tcp_connection_counter_ctx_t *ctx) {
	int err;
	GHashTableIter iter;

	assert(ctx);

	err = configure_files(ctx);
	if (err) {
		TCP_CONNECTION_LOG("Failed to configure files\n");
		goto out;
	}

	ctx->connection_data = g_hash_table_new_full(connection_data_hash, connection_data_equal, g_free, g_free);
	if (!ctx->connection_data) {
		TCP_CONNECTION_LOG("Failed to alloc connection hash table\n");
		err = 1;
		goto out;
	}

	ctx->failed_connection_data = g_hash_table_new_full(failed_connection_data_hash, failed_connection_data_equal, g_free, g_free);
	if (!ctx->failed_connection_data) {
		TCP_CONNECTION_LOG("Failed to alloc failed connection hash table\n");
		err = 1;
		goto out;
	}

out:
	if (err) {
		clean_global_context(ctx);
	}

	return err;
}

static void free_interfaces_ctx(tcp_connection_counter_ctx_t *ctx)
{
	assert (ctx);

	if (ctx->interfaces_data) {
		for (int i = 0; i < ctx->interfaces_count; i++) {
			clean_pcup(&ctx->interfaces_data[i]);
			ctx->interfaces_data[i].interface_name = NULL;
		}

		free(ctx->interfaces_data);
		ctx->interfaces_data = NULL;
	}
	
	free_interfaces_names_set(ctx);
}

static int configure_interfaces_ctx(tcp_connection_counter_ctx_t *ctx)
{
	int err;

	assert(ctx);

	err = configure_interfaces_names_set(ctx);
	if (err) {
		TCP_CONNECTION_LOG("Failed to configure interfaces set\n");
		goto out;
	}

	ctx->interfaces_data = (tcp_connection_counter_interface_ctx_t *)calloc(ctx->interfaces_count, sizeof(*(ctx->interfaces_data)));
    if (!ctx->interfaces_data) {
        TCP_CONNECTION_LOG("Failed to alloc memory for interfaces data\n");
		err = 1;
		goto out;
	}

	for (int i = 0; i < ctx->interfaces_count; i++) {
		ctx->interfaces_data[i].interface_name = ctx->interface_names[i];
		
		err = configure_pcap(&ctx->interfaces_data[i]);
		if (err) {
			TCP_CONNECTION_LOG("Failed to configure pcap interface\n");
			goto out;
		}
	}

out:
	if (err) {
		free_interfaces_names_set(ctx);
	}
	
	return err;
}

int main(int argc, char **argv)
{
	tcp_connection_counter_ctx_t ctx;

	int is_help;
	int ret = 0;

	memset(&ctx, 0, sizeof(ctx));

	signal(SIGINT, int_signal_handler);

	read_options(argc, argv, &ctx, &is_help);
	if (is_help) {
		goto out;
	}

	ret = configure_global_context(&ctx);
	if (ret) {
		TCP_CONNECTION_LOG("Failed to configure global context\n");
		goto out;
	}

	ret = configure_interfaces_ctx(&ctx);
    if (ret) {
		TCP_CONNECTION_LOG("Failed to configure interfaces context\n");
		goto out;
	}

    context = &ctx;

	ret = run_pcap(&ctx);
	if (ret) {
		TCP_CONNECTION_LOG("tcp monitor run with an error\n");
		goto out;
	}

out:
	free_interfaces_ctx(&ctx);
	clean_global_context(&ctx);

    return ret;
}
