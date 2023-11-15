#include "tcp_monitor.h"

#include <poll.h>

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

	interface_ctx->fd = pcap_get_selectable_fd(interface_ctx->handle);
	if (interface_ctx->fd < 0) {
		ret = pcap_setnonblock(interface_ctx->handle, TRUE, errbuf);
		if (ret < 0) {
			TCP_CONNECTION_LOG("Couldn't set interface %s to non-blocking: %s\n", interface_ctx->interface_name, errbuf);
			goto out;
		}
	}

out:
	if (ret) {
		clean_pcup(interface_ctx);
	}

	return ret;
}

int run_pcap(tcp_connection_counter_ctx_t *ctx)
{
	struct pcap_pkthdr *header;
	const uint8_t *packet;
	int err = 0;
	struct pollfd *poll_fds;
	int active_fd_num;

	assert(ctx);

	poll_fds = (struct pollfd*) calloc(ctx->interfaces_count, sizeof(*poll_fds));
	if (!poll_fds) {
		TCP_CONNECTION_LOG("Failed to allocate memory for poll file descriptors\n");
		err = 1;
		goto out;
	}

	for (int i = 0; i < ctx->interfaces_count; i++) {
		poll_fds[i].fd = ctx->interfaces_data[i].fd;
		poll_fds[i].events = POLLIN;
	}

	while (keep_running)
	{
		err = poll(poll_fds, ctx->interfaces_count, TO_MS_MILISECONDS);
		if (err < 0 && (errno == EINTR)) {
			err = 0;
		} else if (err < 0) {
			TCP_CONNECTION_LOG("Interface poll ended with error: %s\n", strerror(errno));
			goto out;
		} else if (err > 0) {
			active_fd_num = err;
			err = 0;
		}

		if ((err == 0) && (active_fd_num == 0)) {
			continue;
		}

		for (int i = 0; (i < ctx->interfaces_count) && active_fd_num; i++) {
			if (!(poll_fds[i].revents & POLLIN)) {
				continue;
			}
			active_fd_num--;

			err = pcap_next_ex(ctx->interfaces_data[i].handle, &header, &packet);
			if (err < 0) {
				TCP_CONNECTION_LOG("An error occured during packet processing on interface %s: %s\n",
					ctx->interfaces_data[i].interface_name, pcap_geterr(ctx->interfaces_data[i].handle));
				goto out;
			} else if (err == 0) {
				continue;
			}

			err = process_packet(ctx, packet);
			if (err) {
				TCP_CONNECTION_LOG("An error occured during packet processing on interface %s\n",
					ctx->interface_name_from_cmd);
				break;
			}
		}
	}

out:
	free(poll_fds);
	return err;
}
