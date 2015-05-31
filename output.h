/**
 * \file output.h
 *
 * Simple DNS Sniffer - DNS parsing / output
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef OUTPUT_H
#define OUTPUT_H

#include <pcap/pcap.h>
#include "dissect.h"

/**
 * Dissect a DNS payload, ignoring any malformed packets.
 *
 * \param[in] dpkt Dissected packet
 * \param[in] hdr  Pcap packet header
 * \return 1 on a fatal error, 0 otherwise.
 */
int output_dns(struct dispkt *dpkt, struct pcap_pkthdr *hdr);

#endif /* OUTPUT_H */

