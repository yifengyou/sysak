#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
//#include <limits.h>
//#include <signal.h>
//#include <time.h>
#include <string.h>
#include <errno.h>
//#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "irqoff.h"

#define MAX_SYMS 300000
#define PERF_MAX_STACK_DEPTH	127

static int sym_cnt;
extern  FILE *filep;

static int ksym_cmp(const void *p1, const void *p2)
{
	return ((struct ksym *)p1)->addr - ((struct ksym *)p2)->addr;
}

int load_kallsyms(struct ksym **pksyms)
{
	struct ksym *syms;
	FILE *f = fopen("/proc/kallsyms", "r");
	char func[256], buf[256];
	char symbol;
	void *addr;
	int i = 0;

	if (!f)
		return -ENOENT;

	syms = malloc(MAX_SYMS * sizeof(struct ksym));
	if (!syms) {
		fclose(f);
		return -ENOMEM;
	}

	while (!feof(f)) {
		if (!fgets(buf, sizeof(buf), f))
			break;
		if (sscanf(buf, "%p %c %s", &addr, &symbol, func) != 3)
			break;
		if (!addr)
			continue;
		syms[i].addr = (long) addr;
		syms[i].name = strdup(func);
		i++;
		if (i > MAX_SYMS) {
			printf("Warning: no space on ksym array!\n");
			break;
		}
	}
	fclose(f);
	sym_cnt = i;
	qsort(syms, sym_cnt, sizeof(struct ksym), ksym_cmp);
	*pksyms = syms;
	return 0;
}

struct ksym *ksym_search(long key, struct ksym *syms)
{
	int start = 0, end = sym_cnt;
	int result;

	/* kallsyms not loaded. return NULL */
	if (sym_cnt <= 0)
		return NULL;

	while (start < end) {
		size_t mid = start + (end - start) / 2;

		result = key - syms[mid].addr;
		if (result < 0)
			end = mid;
		else if (result > 0)
			start = mid + 1;
		else
			return &syms[mid];
	}

	if (start >= 1 && syms[start - 1].addr < key &&
	    key < syms[start].addr)
		/* valid ksym */
		return &syms[start - 1];

	/* out of range. return _stext */
	return &syms[0];
}

static void print_ksym(__u64 addr, struct ksym *psym)
{
	struct ksym *sym;

	if (!addr)
		return;

	sym = ksym_search(addr, psym);
	fprintf(filep, "<0x%llx> %s\n", addr, sym->name);
}

void print_stack(int fd, __u32 ret, struct ksym *syms)
{
	int i;
	__u64 ip[PERF_MAX_STACK_DEPTH] = {};

	if (bpf_map_lookup_elem(fd, &ret, &ip) == 0) {
		for (i = 0; i < PERF_MAX_STACK_DEPTH - 1; i++)
			print_ksym(ip[i], syms);
	} else {
		if ((int)(ret) < 0)
		fprintf(filep, "<0x0000000000000000>:error=%d\n", (int)(ret));
	}
}

