/**
 * \file proc.h
 *
 * Simple DNS Sniffer - Process lookup
 * Copyright (C) 2015 Tim Hentenaar.
 *
 * This code is licenced under the Simplified BSD License.
 * See the LICENSE file for details.
 */

#ifndef PROC_H
#define PROC_H

#include "dissect.h"

/**
 * Lookup which process owns the destination port sepcified
 * in dpkt->dp.
 */
void lookup_proc(char *buffer, size_t s, struct dispkt *dpkt);

#endif /* PROC_H */

