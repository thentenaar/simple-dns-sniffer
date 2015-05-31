/**
 * Simple DNS Sniffer - DNS parsing / output
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <features.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>

#include "dissect.h"

/**
 * DNS header
 */
struct dnshdr {
	uint16_t id;
	uint16_t flags;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
} __attribute__((packed));

/**
 * Basic DNS record types (RFC 1035)
 */
static const char *dns_types[] = {
	"UNKN",  /* Unsupported / Invalid type */
	"A",     /* Host Address */
	"NS",    /* Authorative Name Server */
	"MD",    /* Mail Destination (Obsolete) */
	"MF",    /* Mail Forwarder   (Obsolete) */
	"CNAME", /* Canonical Name */
	"SOA",   /* Start of Authority */
	"MB",    /* Mailbox (Experimental) */
	"MG",    /* Mail Group Member (Experimental) */
	"MR",    /* Mail Rename (Experimental) */
	"NULL",  /* Null Resource Record (Experimental) */
	"WKS",   /* Well Known Service */
	"PTR",   /* Domain Name Pointer */
	"HINFO", /* Host Information */
	"MINFO", /* Mailbox / Mail List Information */
	"MX",    /* Mail Exchange */
	"TXT",   /* Text Strings */
	"AAAA"   /* IPv6 Host Address (RFC 1886) */
};

static u_char buf[BUFSIZ]; /* Label buffer */
static char dbuf[BUFSIZ];  /* Data bufffer */

/**
 * Skip a DNS label.
 *
 * \param[in] label Pointer to the label
 * \return Pointer to the byte following the label
 */
static u_char *skip_dns_label(u_char *label)
{
	u_char *tmp;

	if (!label) return NULL;
	if (*label & 0xc0)
		return label + 2;

	tmp = label;
	while (*label) {
		tmp += *label + 1;
		label = tmp;
	}
	return label + 1;
}

/**
 * Convert a DNS label (which may contain pointers) to
 * a string by way of the given destination buffer.
 *
 * \param[in] label     Pointer to the start of the label
 * \param[in] dest      Destination buffer
 * \param[in] dest_size Destination buffer size
 * \param[in] payload   Start of the packet
 * \param[in] end       End of the packet
 * \return dest
 */
static u_char *dns_label_to_str(u_char **label, u_char *dest,
                               size_t dest_size,
                               const u_char *payload,
                               const u_char *end)
{
	u_char *tmp, *dst = dest;

	if (!label || !*label || !dest)
		goto err;

	*dest = '\0';
	while (*label < end && **label) {
		if (**label & 0xc0) { /* Pointer */
			tmp = (u_char *)payload;
			tmp += ntohs(*(uint16_t *)(*label)) & 0x3fff;
			while (tmp < end && *tmp) {
				if (dst + *tmp >= dest + dest_size)
					goto err;
				memcpy(dst, tmp+1, *tmp);
				dst += *tmp; tmp += *tmp + 1;
				if (dst > dest + dest_size) goto err;
				*dst = '.'; dst++;
			};
			*label += 2;
		} else { /* Label */
			if ((*label + **label) >= end)
				goto err;
			if (**label + dst >= dest + dest_size)
				goto err;
			memcpy(dst, *label + 1, **label);
			dst += **label;
			if (dst > dest + dest_size) goto err;
			*label += **label + 1;
			*dst = '.'; dst++;
		}
	}

	*(--dst) = '\0';
	return dest;
err:
	if (dest) *dest = '\0';
	return dest;
}

/**
 * Dissect a DNS payload, ignoring any malformed packets.
 *
 * \param[in] dpkt Dissected packet
 * \param[in] hdr  Pcap packet header
 * \return 1 on a fatal error, 0 otherwise.
 */
int output_dns(struct dispkt *dpkt, struct pcap_pkthdr *hdr)
{
	struct dnshdr *dnsh;
	u_char *tmp;
	u_char *label;
	const char *data;
	const u_char *end;
	uint16_t len, qtype = 0;
	int i;

	/* Ensure the packet is valid */
	end = dpkt->payload + (hdr->len - dpkt->payload_offset);
	if (end < dpkt->payload)
		goto ret;

	dnsh = (struct dnshdr *)(dpkt->payload);
	dnsh->id      = ntohs(dnsh->id);
	dnsh->flags   = ntohs(dnsh->flags);
	dnsh->qdcount = ntohs(dnsh->qdcount);
	dnsh->ancount = ntohs(dnsh->ancount);
	dnsh->nscount = ntohs(dnsh->nscount);
	dnsh->arcount = ntohs(dnsh->arcount);

	/* Disregard malformed packets */
	if (!dnsh->ancount || !dnsh->qdcount)
		return 0;

	/* Parse the Question section */
	tmp = (u_char *)(dpkt->payload + 12);
	for (i=0;i<dnsh->qdcount;i++) {
		/* Get the first question's label and question type */
		if (!qtype) {
			label = dns_label_to_str(&tmp, buf, BUFSIZ,
			                         dpkt->payload, end);
			tmp++;
			qtype = ntohs(*(uint16_t *)tmp);
		} else {
			if (*tmp & 0xc0) tmp += 2;
			else tmp = skip_dns_label(tmp);
		}

		/* Skip type and class */
		tmp += 4;
		if (tmp >= end) goto ret;
	}

	/* Output the answer corresponding to the question */
	if (!qtype) goto ret;
	for (i=0;i<dnsh->ancount;i++) {
		tmp = skip_dns_label(tmp);
		if (tmp + 10 > end) goto ret;

		/* Get the type, and skip class and ttl */
		len = ntohs(*(uint16_t *)tmp); tmp += 8;
		if (len == qtype) break;

		/* Skip ahead to the next answer */
		tmp += ntohs(*(uint16_t *)tmp) + 2;
		if (tmp > end) goto ret;
	}

	/* Get the data field length */
	len = ntohs(*(uint16_t *)tmp); tmp += 2;
	if (qtype == 28) qtype = 17; /* 28 = AAAA */
	else if (qtype > 16) qtype = 0;

	/* Now, handle the data based on type */
	switch (qtype) {
		case 1: /* A */
			data = inet_ntop(AF_INET, tmp, dbuf, BUFSIZ);
		break;
		case 2:  /* NS */
		case 5:  /* CNAME */
		case 12: /* PTR */
			data = (char *)dns_label_to_str(
				&tmp, (u_char *)dbuf, BUFSIZ,
				dpkt->payload, tmp + len
			);
		break;
		case 10: /* NULL */
			data = "NULL";
		break;
		case 15: /* MX (16-bit priority / label) */
			i = snprintf(dbuf, 7, "%u ", ntohs(*(uint16_t *)tmp));
			tmp += 2;
			data = (char *)dns_label_to_str(
				&tmp, (u_char *)(dbuf + i), BUFSIZ - i,
				dpkt->payload, tmp + len - 2
			);
			data = dbuf;
		break;
		case 16: /* TXT (1 byte text length / text) */
			if (*tmp <= len && tmp + len < end) {
				memcpy(dbuf, tmp+1, *tmp);
				dbuf[*tmp+1] = '\0';
			} else *dbuf = '\0';
			data = dbuf;
		break;
		case 17: /* AAAA */
			data = inet_ntop(AF_INET6, tmp, dbuf, BUFSIZ);
		break;
		default:
			/* Ignore unhandled RR types */
			*dbuf = '\0';
			data = dbuf;
	}

	/* Print the output. */
	printf("%ld %-5s %-30s %s\n", hdr->ts.tv_sec,
	       dns_types[qtype], label, data);

ret:
	return 0;
}

