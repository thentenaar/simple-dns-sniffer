/**
 * \file dissect.h
 *
 * Simple DNS Sniffer - Packet Dissection
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef DISSECT_H
#define DISSECT_H

#include <stdint.h>
#include <netinet/in.h>
#include <pcap/pcap.h>

/**
 * Representation of a dissected TCP/UDP packet.
 */
struct dispkt {
	union { /**< Source address */
		struct in6_addr ip6;
		uint32_t        ip;
	} sa;

	union { /**< Destination address */
		struct in6_addr ip6;
		uint32_t        ip;
	} da;

	uint16_t sp;           /**< Source port */
	uint16_t dp;           /**< Destination port */
	int      family;       /**< Address family */
	uint8_t  ip_proto;     /**< IP protocol */
	size_t payload_offset; /**< Payload offset within the packet */
	const u_char *payload; /**< Packet payload */
};

/**
 * Dissect a captured TCP/UDP packet.
 *
 * Because of the filter we're using, we can safely assume that
 * this is either TCP or UDP on top of IP. We also handle the case
 * where the packet may have become corrupted in several places,
 * by checking the bounds of \a data, and by double-checking the
 * protocol identifier(s).
 *
 * \param[in] lnk  Pcap link type
 * \param[in] hdr  Pcap header
 * \param[in] data Packet data
 * \param[in] dpkt Dissected packet struct to fill in
 * \return 0 on success, 1 on failure
 */
int dissect_ip_packet(int lnk, struct pcap_pkthdr *hdr,
                      const u_char *data, struct dispkt *dpkt);

/**
 * Determine if the destination address given
 * in \a dpkt belongs to an interface local to
 * this machine. (UNUSED)
 *
 * \param[in] dpkt Dissected packet struct
 * \return 1 if the destination is local, 0 otherwise.
 */
int is_destination_local(struct dispkt *dpkt);

#endif	/* DISSECT_H */

