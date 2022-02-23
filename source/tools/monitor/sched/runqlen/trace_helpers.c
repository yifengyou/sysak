/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
// Copyright (c) 2020 Wenbo Zhang
//
// Based on ksyms improvements from Andrii Nakryiko, add more helpers.
// 28-Feb-2020   Wenbo Zhang   Created this.
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <time.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <limits.h>
#include "trace_helpers.h"
//#include "uprobe_helpers.h"
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })

static void print_stars(unsigned int val, unsigned int val_max, int width)
{
	int num_stars, num_spaces, i;
	bool need_plus;

	num_stars = min(val, val_max) * width / val_max;
	num_spaces = width - num_stars;
	need_plus = val > val_max;

	for (i = 0; i < num_stars; i++)
		printf("*");
	for (i = 0; i < num_spaces; i++)
		printf(" ");
	if (need_plus)
		printf("+");
}

void print_linear_hist(unsigned int *vals, int vals_size, unsigned int base,
		       unsigned int step, const char *val_type)
{
	int i, stars_max = 40, idx_min = -1, idx_max = -1;
	unsigned int val, val_max = 0;

	for (i = 0; i < vals_size; i++) {
		val = vals[i];
		if (val > 0) {
			idx_max = i;
			if (idx_min < 0)
				idx_min = i;
		}
		if (val > val_max)
			val_max = val;
	}

	if (idx_max < 0)
		return;

	printf("     %-13s : count     distribution\n", val_type);
	for (i = idx_min; i <= idx_max; i++) {
		val = vals[i];
		printf("        %-10d : %-8d |", base + i * step, val);
		print_stars(val, val_max, stars_max);
		printf("|\n");
	}
}
