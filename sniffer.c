/**
 * Simple DNS Sniffer
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <net/if.h>
#include <pcap/pcap.h>

#include "dissect.h"
#include "output.h"

/**
 * Filter for packets on port 53, presumably DNS packets,
 * with the QR bit set (response).
 */
static const char *filter =
	"port 53 and ("
	"(udp and (not udp[10] & 128 = 0)) or"
	"(tcp and (not tcp[((tcp[12] & 0xf0) >> 2) + 2] & 128 = 0))"
	")";
static char errbuf[PCAP_ERRBUF_SIZE];

/* Command-line Args */
static char intf[IFNAMSIZ] = { 'a', 'n', 'y', '\0' };
static int snaplen = 2048;
static int timeout = 1000;
static int promisc = 0;

/**
 * Get the next packet and dissect it.
 *
 * \param[in] session   pcap session
 * \param[in] link_type pcap link type
 * \return 0 on success, 1 on error
 */
static int next_packet(pcap_t *session, int link_type)
{
	struct pcap_pkthdr *packet_hdr = NULL;
	const u_char *packet_data = NULL;
	struct dispkt dpkt;
	int i;

	i = pcap_next_ex(session, &packet_hdr, &packet_data);
	if (i < 0) {
		pcap_perror(session, "Error capturing packet: ");
		goto ret1;
	} else if (!i) goto ret;

	if (!packet_hdr || !packet_data)
		goto err;

	/**
	 * caplen should always be <= len, otherwise it's likely
	 * that the packet that pcap received was somehow corrupted.
	 *
	 * This should never happen, unless there's memory corruption
	 * going on, or a really nasty bug in libpcap.
	 */
	if (packet_hdr->caplen > packet_hdr->len)
		goto err;

	/* Dissect the link/IP/IP_PROTO layers of the packet */
	if (dissect_ip_packet(link_type, packet_hdr, packet_data, &dpkt))
		goto ret;

	/* Output a representation of the DNS payload */
	if (output_dns(&dpkt, packet_hdr))
		goto ret;

ret:
	return 0;

err:
	fprintf(stderr, "Dropping corrupted packet\n");

ret1:
	return 1;
}

/**
 * Display basic usage info.
 */
static void usage(const char *procname)
{
	printf("%s [-i interface] [-s snaplen] [-t timeout] [-p]\n\n"
	       "\t-i interface: Interface to capture on\n"
	       "\t-s snaplen:   Snapshot length / packet buffer size\n"
	       "\t-t timeout:   Maximum read timeout (in milliseconds)\n"
	       "\t-p:           Enable promiscuous mode\n\n"
	       "\t Defaults: -i any -s %d -t %d\n",
	       procname, snaplen, timeout);
	exit(EXIT_FAILURE);
}

int main(int argc, char *argv[])
{
	pcap_t *session = NULL;
	int link_type, i;
	bpf_u_int32 netmask, ip;
	struct bpf_program bpf;

	/* Evaluate args with a simple O(n) loop */
	for (i=1;i<argc;i++) {
		if (!argv[i] || argv[i][0] != '-')
			goto invalid_arg;

		if (argv[i][1] == 'p') {
			promisc = 1;
			continue;
		} else if (argv[i][1] == 'h')
			usage(argv[0]);

		/* Make sure we don't try to go beyond argv[]'s bounds */
		if (i + 1 >= argc)
			goto invalid_arg;

		switch (argv[i][1]) {
			case 'i':
				strncpy(intf, argv[++i], IFNAMSIZ);
			break;
			case 's':
				snaplen = atoi(argv[++i]);
			break;
			case 't':
				timeout = atoi(argv[++i]);
			break;
			default:
				goto invalid_arg;
		}
	}

	/* Create a new capture session */
	memset(errbuf, 0, PCAP_ERRBUF_SIZE);
	session = pcap_open_live(intf, snaplen, promisc, timeout, errbuf);
	if (!session) {
		fprintf(stderr, "Unable to open '%s': %s\n",
		        intf, errbuf);
		goto err;
	}

	/* Ensure that we support the interface's link-level header */
	link_type = pcap_datalink(session);
	if (link_type != DLT_LINUX_SLL && link_type != DLT_EN10MB &&
	    link_type != DLT_IPV4 && link_type != DLT_IPV6) {
		fprintf(stderr, "Unsupported link type: %d\n", link_type);
		goto err;
	}

	/* Get the IP and netmask (for the filter) */
	if (pcap_lookupnet(intf, &ip, &netmask, errbuf) == -1) {
		ip      = 0;
		netmask = 0;
	}

	/* Compile and apply our filter (without BPF optimization) */
	if (pcap_compile(session, &bpf, filter, 0, netmask) == -1 ||
	    pcap_setfilter(session, &bpf) == -1) {
	    pcap_perror(session, "Error installing filter: ");
	    goto err;
	}

	/* Grab and dissect packets until an error occurs */
	while (!next_packet(session, link_type));

err:
	if (session) pcap_close(session);
	return EXIT_FAILURE;

invalid_arg:
	fprintf(stderr, "Invalid argument: %s\n", argv[i]);
	usage(argv[0]);
	return EXIT_FAILURE;
}

