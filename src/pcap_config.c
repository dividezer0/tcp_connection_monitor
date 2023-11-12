#include "tcp_monitor.h"

void clean_pcup(tcp_connection_counter_interface_ctx_t *ctx)
{
	pcap_freecode(&ctx->compiled_filter_expr);
	if (ctx->handle) {
		pcap_close(ctx->handle);
	}
	ctx->handle = NULL;
}

int configure_pcap(tcp_connection_counter_interface_ctx_t *interface_ctx)
{
	int ret;
	bpf_u_int32 mask;
	bpf_u_int32 net;
	char errbuf[PCAP_ERRBUF_SIZE];

	assert(interface_ctx);

	ret = pcap_lookupnet(interface_ctx->interface_name, &net, &mask, errbuf);
	if (ret) {
		TCP_CONNECTION_LOG("Couldn't get netmask for device %s: %s\n", interface_ctx->interface_name, errbuf);
		net = 0;
		mask = 0;
	}

	interface_ctx->handle = pcap_open_live(interface_ctx->interface_name, SNAP_LEN, PROMISCOUS, TO_MS_MILISECONDS, errbuf);
	if (!interface_ctx->handle) {
		TCP_CONNECTION_LOG("Couldn't open device %s: %s\n", interface_ctx->interface_name, errbuf);
		ret = 1;
		goto out;
	}

	ret = pcap_compile(interface_ctx->handle, &interface_ctx->compiled_filter_expr, TCP_FILTER, 0, net) ;
	if (ret) {
		TCP_CONNECTION_LOG("Couldn't parse filter %s: %s\n", TCP_FILTER, pcap_geterr(interface_ctx->handle));
		goto out;
	}

	ret = pcap_setfilter(interface_ctx->handle, &interface_ctx->compiled_filter_expr);
	if (ret) {
		TCP_CONNECTION_LOG("Couldn't install filter %s: %s\n", TCP_FILTER, pcap_geterr(interface_ctx->handle));
		goto out;
	}

out:
	if (ret) {
		clean_pcup(interface_ctx);
	}

	return ret;
}

int run_pcap(tcp_connection_counter_interface_ctx_t *ctx)
{
	struct pcap_pkthdr header;
	const uint8_t *packet;
	int ret = 0;

	assert(ctx);

	while (1)
	{
		packet = pcap_next(ctx->handle, &header);
        if (!keep_running) {
            break;
        }

		ret = process_packet(ctx, packet);
		if (ret) {
			TCP_CONNECTION_LOG("An error occured during packet processing on interface %s\n",
				ctx->interface_name);
			break;
		}
	}

	return ret;
}