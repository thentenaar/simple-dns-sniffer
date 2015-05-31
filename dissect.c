/**
 * Simple DNS Sniffer - Packet Dissection
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ifaddrs.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <linux/if.h>

#include "dissect.h"

/**
 * Ensure that pkt is between data and data + len.
 *
 * If this evaluates to 1, then PKT is beyond the bounmds of
 * the data passed to us by libpcap.
 */
#define check_packet_ptr(PKT, DATA, LEN) ((PKT) >= ((DATA) + (LEN)))

/**
 * Dissect a captured TCP/UDP packet.
 *
 * Because of the filter we're using, we can safely assume that
 * this is either TCP or UDP on top of IP. We also handle the case
 * where the packet may have become corrupted in several places,
 * by checking the bounds of \a data, and by double-checking the
 * protocol identifier(s).
 *
 * \param[in]     lnk  Pcap link type
 * \param[in]     hdr  Pcap header
 * \param[in]     data Packet data
 * \param[in,out] dpkt Dissected packet struct to fill in
 */
int dissect_ip_packet(int lnk, struct pcap_pkthdr *hdr,
                       const u_char *data, struct dispkt *dpkt)
{
	const u_char *pkt = data;
	uint16_t protocol = 0;

	/* Get the protocol identifier from the link layer */
	switch (lnk) {
		case DLT_LINUX_SLL: /* sockaddr_ll "cooked" packet */
			protocol = ntohs(*(uint16_t *)(pkt + 14));
			pkt += 16;
		break;
		case DLT_EN10MB: /* Ethernet */
			protocol = ntohs(*(uint16_t *)(pkt + ETH_HLEN - 2));
			pkt += ETH_HLEN;
		break;
		case DLT_IPV4: /* Raw IPv4 */
			protocol = ETH_P_IP;
		break;
		case DLT_IPV6: /* Raw IPv6 */
			protocol = ETH_P_IPV6;
		break;
	}

	if (check_packet_ptr(pkt, data, hdr->len) || !protocol)
		goto err;

	/* Get the IP protocol used, and seek past the IP header. */
	switch (protocol) {
		case ETH_P_IP:
			protocol = ((struct iphdr *)pkt)->protocol;
			dpkt->sa.ip  = ((struct iphdr *)pkt)->saddr;
			dpkt->da.ip  = ((struct iphdr *)pkt)->daddr;
			dpkt->family = AF_INET;
			pkt = pkt + (((struct iphdr *)pkt)->ihl << 2);
		break;
		case ETH_P_IPV6:
			dpkt->sa.ip6 = ((struct ip6_hdr *)pkt)->ip6_src;
			dpkt->da.ip6 = ((struct ip6_hdr *)pkt)->ip6_dst;
			dpkt->family = AF_INET6;
			protocol = ((struct ip6_hdr *)pkt)->ip6_nxt;
			pkt += 40; /* IPv6 header langth */
		break;
		default:
			protocol = 0;
	}

	if (check_packet_ptr(pkt, data, hdr->len) || !protocol)
		goto err;

	/* Now handle the TCP/UDP layer */
	dpkt->ip_proto = protocol & 0xff;
	switch (dpkt->ip_proto) {
		case IPPROTO_UDP:
			dpkt->sp = ntohs(((struct udphdr *)pkt)->source);
			dpkt->dp = ntohs(((struct udphdr *)pkt)->dest);
			pkt += 8;
		break;
		case IPPROTO_TCP:
			dpkt->sp = ntohs(((struct tcphdr *)pkt)->source);
			dpkt->dp = ntohs(((struct tcphdr *)pkt)->dest);
			pkt += (((struct tcphdr *)pkt)->doff << 2) + 1;
		break;
		default:
			protocol = 0;
	}

	if (check_packet_ptr(pkt, data, hdr->len) || !protocol)
		goto err;

	dpkt->payload = pkt;
	dpkt->payload_offset = pkt - data;
	return 0;

err:
	return 1;
}

/**
 * Determine if the destination address given
 * in \a dpkt belongs to an interface local to
 * this machine. (UNUSED)
 */
int is_destination_local(struct dispkt *dpkt)
{
	struct ifaddrs *addrs, *ifa;
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	if (!dpkt) return 0;

	/* First, ensure the receiving interface is local */
	if (getifaddrs(&addrs))
		return 0;

	for (ifa=addrs;ifa;ifa=ifa->ifa_next) {
		/* Ignore any interfaces that aren't usable */
		if (!ifa->ifa_addr || !(ifa->ifa_flags & IFF_UP))
			continue;
		if (ifa->ifa_addr->sa_family != dpkt->family)
			continue;

		/* Compare addresses */
		if (dpkt->family == AF_INET) {
			sin = (struct sockaddr_in *)(ifa->ifa_addr);
			if (sin->sin_addr.s_addr == dpkt->da.ip)
				break;
		} else {
			sin6 = (struct sockaddr_in6 *)(ifa->ifa_addr);
			if (!memcmp(sin6, &(dpkt->da.ip6),
			     sizeof(struct in6_addr))) break;
		}
	}

	freeifaddrs(addrs);
	if (!ifa) return 0;
	return 1;
}

