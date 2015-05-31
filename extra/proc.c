/**
 * DNS Sniffer Example - Process lookup
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/types.h>
#include <netinet/in.h>

#include "dissect.h"
#include "proc.h"

/* Format strings for parsing /proc/net/{tcp,udp,tcp6,udp6} */
const char *inet_fmt  = "%d: %x:%4x %x:%4x %x %x:%x %x:%x %x %d %d %lu ";
const char *inet6_fmt = "%d: %8x%8x%8x%8x:%4x %8x%8x%8x%8x:%4x %x %x:%x "
                        "%x:%x %x %d %d %lu ";

/**
 * Scan a line from /proc/net/{tcp,udp,tcp6,udp6} and if
 * the local address matches, get the inode number for
 * that socket.
 *
 * \param[in] buffer Line buffer
 * \param[in] dpkt   Dissected packet struct
 * \return The inode number, or 0 on error.
 */
static unsigned long get_inode_for_dest(char *buffer, struct dispkt *dpkt)
{
	struct in_addr  in;
	struct in6_addr in6;
	uint16_t port;
	unsigned long inode, tmp;
	int i;

	if (!buffer || !dpkt)
		return 0;

	if (dpkt->family == AF_INET6) {
		i = sscanf(buffer, inet6_fmt, &tmp,
		           (uint32_t *)(&in6.s6_addr[0]),
		           (uint32_t *)(&in6.s6_addr[4]),
		           (uint32_t *)(&in6.s6_addr[8]),
		           (uint32_t *)(&in6.s6_addr[12]),
		           &port, &tmp, &tmp, &tmp, &tmp, &tmp,
		           &tmp, &tmp, &tmp, &tmp, &tmp, &tmp,
		           &tmp, &tmp, &inode);
		if (i < 20)
			return 0;
		if (!memcmp(&in6, &(dpkt->da.ip6), sizeof(struct in6_addr)))
			if (port == dpkt->dp)
				return inode;
	} else {
		i = sscanf(buffer, inet_fmt, &tmp, &in.s_addr, &port,
		           &tmp, &tmp, &tmp, &tmp, &tmp, &tmp, &tmp,
		           &tmp, &tmp, &tmp, &inode);
		if (i < 14)
			return 0;
		if (!memcmp(&in.s_addr, &(dpkt->da.ip), sizeof(struct in_addr)))
			if (port == dpkt->dp)
				return inode;
	}

	return 0;
}

/**
 * Get the process's name from its cmdline entry.
 */
static void get_procname(char *buffer, size_t s, unsigned long pid)
{
	FILE *fp;
	char pathbuf[25], linebuf[255], *tmp;

	snprintf(pathbuf, sizeof(pathbuf), "/proc/%lu/cmdline", pid);
	if (!(fp = fopen(pathbuf, "r")))
		return;
	if (fgets(linebuf, sizeof(linebuf), fp)) {
		tmp = linebuf;
		while (*tmp != ' ' && *tmp != '\0') tmp++;
		*tmp = '\0';
		do { tmp--; } while (*tmp != '/');
		tmp[6] = '\0';
		snprintf(buffer, s, "%s/%lu", tmp, pid);
	}
	fclose(fp);
}

/**
 * Scan a pid's file descriptors, looking for our
 * target socket.
 */
static void process_pid(char *buffer, size_t s, unsigned long pid,
                        unsigned long inode)
{
	DIR *dir;
	struct dirent *de;
	size_t len;
	char pathbuf[25], linkbuf[25], target[25];

	/* Root through the process's fds */
	snprintf(target, sizeof(target), "socket:[%lu]", inode);
	snprintf(pathbuf, sizeof(pathbuf), "/proc/%lu/fds", pid);
	if (!(dir = opendir(pathbuf)))
		return;

	while (!*buffer && (de = readdir(dir))) {
		snprintf(pathbuf, sizeof(pathbuf),
			 "/proc/%lu/fds/%s", pid, de->d_name);
		len = readlink(pathbuf, linkbuf, sizeof(linkbuf));
		if (len <= 0 || len > sizeof(linkbuf))
			return;
		linkbuf[len] = '\0';

		if (!strcmp(linkbuf, target))
			get_procname(buffer, s, pid);
	}

	closedir(dir);

}

/**
 * Lookup which process owns the destination port sepcified
 * in dpkt->dp.
 */
void lookup_proc(char *buffer, size_t s, struct dispkt *dpkt)
{
	char *net_file;
	DIR *proc_dir;
	FILE *fp;
	struct dirent *de;
	unsigned long inode = 0, pid;
	char linebuf[256], *endptr;

	if (!buffer || !dpkt)
		return;

	*buffer = '\0';
	if (dpkt->ip_proto == IPPROTO_TCP) {
		if (dpkt->family == AF_INET6)
			net_file = "/proc/net/tcp6";
		else net_file = "/proc/net/tcp";
	} else {
		if (dpkt->family == AF_INET6)
			net_file = "/proc/net/udp6";
		else net_file = "/proc/net/udp";
	}

	/* Open the file from /proc/net and try to find the inode */
	if (!(fp = fopen(net_file, "r")))
		return;

	while (fgets(linebuf, sizeof(linebuf) - 1, fp)) {
		inode = get_inode_for_dest(linebuf, dpkt);
		if (inode > 0) break;
	}

	fclose(fp);
	if (!inode)
		return;

	/* Now that we have the inode, we can probe for the process */
	if (!(proc_dir = opendir("/proc")))
		return;

	while (!*buffer && (de = readdir(proc_dir))) {
		/* Make sure we actually have a base-10 numeric string */
		pid = strtoul(de->d_name, &endptr, 10);
		if (*endptr != '\0')
			continue;
		process_pid(buffer, s, pid, inode);
	}

	closedir(proc_dir);
}

