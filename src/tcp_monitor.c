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

int is_multithread;
pthread_mutex_t log_lock;
pthread_mutex_t output_lock;

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
				ctx->interface_name = optarg;
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


static int configure_interfaces_names_set(tcp_connection_counter_ctx_t *ctx)
{
	int err;

	err = getifaddrs(&ctx->addrs);
	if (err) {
		TCP_CONNECTION_LOG("Failed to get interface addresses: %s", strerror(errno));
		goto out;
	}
	
	ctx->interfaces = g_hash_table_new(g_str_hash, g_str_equal);
	if (!ctx->interfaces) {
		TCP_CONNECTION_LOG("Failed to allocate interfaces list\n");
		err = 1;
		goto out;
	}

	for (struct ifaddrs *addr = ctx->addrs; addr != NULL; addr = addr->ifa_next) {
		if ((strcmp("lo", addr->ifa_name) == 0) || !(addr->ifa_flags & (IFF_RUNNING))) {
			continue;
		}
		
		if (addr->ifa_addr && addr->ifa_addr->sa_family == AF_INET) {
			g_hash_table_add(ctx->interfaces, addr->ifa_name);
		}
	}

out:
	if (err) {
		if (ctx->interfaces) {
			g_hash_table_destroy(ctx->interfaces);
			ctx->interfaces = NULL;
		}
		if (ctx->addrs) {
			freeifaddrs(ctx->addrs);
			ctx->addrs = NULL;
		}
	}

	return err;
}

static int run_threads_and_join(tcp_connection_counter_ctx_t *ctx)
{
	int *thread_ret;
	int ret = 0;

	g_hash_table_foreach(ctx->interfaces, init_thread, ctx);

	if (!keep_running) {
		TCP_CONNECTION_LOG("Failed to init threads\n");

		for (int i = 0; i < ctx->interfaces_count && ctx->interfaces_data[i].interface_name; i++) {
			pthread_cancel(ctx->interfaces_data[i].thread_id);
		}
	}

	for (int i = 0; i < ctx->interfaces_count && ctx->interfaces_data[i].interface_name; i++) {
		pthread_join(ctx->interfaces_data[i].thread_id, &thread_ret);
		if (thread_ret && (*thread_ret)) {
			TCP_CONNECTION_LOG("Thread %i returned %d\n", i, *((int *)thread_ret));
			ret = ret && (*((int *)thread_ret));
		}
	}

	return ret;
}

static int configure_global_context(tcp_connection_counter_ctx_t *ctx) {
	int ret;
	GHashTableIter iter;

	assert(ctx);

	ret = configure_files(ctx);
	if (ret) {
		TCP_CONNECTION_LOG("Failed to configure files\n");
		goto out;
	}

	if (ctx->all_interfaces) {
		ret = configure_interfaces_names_set(ctx);
		if (ret) {
			TCP_CONNECTION_LOG("Failed to configure interfaces set\n");
			goto out;
		}

		ctx->interfaces_count = g_hash_table_size(ctx->interfaces);
	} else {
		ctx->interfaces_count = 1;
	}

	ctx->interfaces_data = (tcp_connection_counter_interface_ctx_t *) calloc(ctx->interfaces_count, sizeof(*(ctx->interfaces_data)));
	if (!ctx->interfaces_data) {
		TCP_CONNECTION_LOG("Failed to alloc memory for interfaces data\n");
		ret = 1;
		goto out;
	}

	if (ctx->all_interfaces && (ctx->interfaces_count == 1)) {
		g_hash_table_iter_init(&iter, ctx->interfaces);
		g_hash_table_iter_next(&iter, &ctx->interface_name, &ctx->interface_name);
	}

out:
	return ret;
}

static int run_tcp_monitor(tcp_connection_counter_ctx_t *ctx) {
	int ret;
	char *interface_name;

	assert(ctx);

	if (ctx->interfaces_count > 1) {
		
		ret = pthread_mutex_init(&log_lock, NULL); 
		if (ret) { 
			TCP_CONNECTION_LOG("Log file mutex init has failed\n"); 
			goto out; 
    	}

		ret = pthread_mutex_init(&output_lock, NULL); 
		if (ret) { 
			TCP_CONNECTION_LOG("Log file mutex init has failed\n"); 
			goto out; 
    	}
	
		is_multithread = 1;

		ret = run_threads_and_join(ctx);
		if (ret) {
			goto out;
		}
	} else {	
		ret = configure_interface_ctx(ctx->interface_name, ctx->interfaces_data);
		if (ret) {
			TCP_CONNECTION_LOG("Failed to configure interface data for interface %s\n", ctx->interfaces_data->interface_name);
			goto out;
		}

		ret = run_pcap(ctx->interfaces_data);
		if (ret) {
			TCP_CONNECTION_LOG("Tcp monitor on interface %s ended with error\n", ctx->interfaces_data->interface_name);
			goto out;
		}
	}

out:
	return ret;
}

static void clean_global_context(tcp_connection_counter_ctx_t *ctx)
{
	assert(ctx);

	for (int i = 0; i < ctx->interfaces_count && ctx->interfaces_data[i].interface_name; i++) {
		interface_ctx_free(&ctx->interfaces_data[i]);
	}
	if (ctx->interfaces_data) {
		free(ctx->interfaces_data);
	}

	if (ctx->interfaces) {
		g_hash_table_destroy(ctx->interfaces);
	}

	if (ctx->addrs) {
		freeifaddrs(ctx->addrs);
	}

	clean_files(ctx);
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
    
    context = &ctx;

	ret = run_tcp_monitor(&ctx);
	if (ret) {
		TCP_CONNECTION_LOG("tcp monitor run with an error\n");
		goto out;
	}

out:
	if (is_multithread) {
		pthread_mutex_destroy(&log_lock); 
		pthread_mutex_destroy(&output_lock);
	}

	clean_global_context(&ctx);

    return ret;
}

