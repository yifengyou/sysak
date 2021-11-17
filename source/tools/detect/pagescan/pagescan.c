/*
 * Page scan tool
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#include <ctype.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include "pagescan.h"
#include "bitops.h"

extern void scan_fragment(struct buddy_info *buddy_info);
extern void scan_movability(struct buddy_info *buddy_info);
extern void scan_movability_help(void);
extern void scan_slabs(char *slabs);
extern void scan_zero_subpages(struct buddy_info *buddy_info);
extern void scan_zero_subpages_in_base(uint64_t raw_pfn, int idx, int end);
extern void scan_exec_vma(struct procmap *procmap, int procmap_num);

struct options {
	pid_t *pids;
	int pid_num;
	bool fragment;
	bool movability;
	bool zero_subpages;
	bool exec_vma;
	char *slabs;
} opt = { 0 };

#define MAX_KCORE_ELF_HEADER_SIZE	32768
struct proc_kcore_data {
	unsigned int flags;
	unsigned int segments;
	char *elf_header;
	size_t header_size;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	Elf32_Phdr *load32;
	Elf32_Phdr *notes32;
	void *vmcoreinfo;
	unsigned int size_vmcoreinfo;
};

static struct proc_kcore_data proc_kcore_data = { 0 };
static struct proc_kcore_data *pkd = &proc_kcore_data;

static int kcore_fd = 0;
static int kpageflags_fd = 0;
static uint64_t g_max_phy_addr;

struct {
	int		exist;
	uint64_t	start_pfn;
} numa_info[MAX_NUMA_NODES];
int nr_numa_node = -1;

/*
 * kernel	vmemmap_base		page_offset_base
 * 3.10		0xffffea0000000000UL	0xffff880000000000UL
 * 4.9		0xffffea0000000000UL	0xffff880000000000UL
 * 4.19		0xffffea0000000000UL	0xffff888000000000UL
 *
 * We use default vmemmap_base and page_offset_base values on kernel 4.9,
 * which is the same on kernel 3.10, and reassign these two values on
 * kernel 4.19 due to kaslr, by kcore.
 */
unsigned long vmemmap_base = 0xffffea0000000000UL;
unsigned long page_offset_base = 0xffff880000000000UL;

/*
 * Routines of kpageflags, i.e., /proc/kpageflags
 */
ssize_t kpageflags_read(void *buf, size_t count, off_t offset)
{
	return pread(kpageflags_fd, buf, count, offset);
}

/*
 * Routines of procmap, i.e., /proc/pid/(s)maps
 */
static int get_memory_map(pid_t pid, struct procmap **p_procmap)
{
	struct procmap *procmap = NULL;
	int procmap_max_num = 128, procmap_num = 0;
	char path[PATH_MAX];
	char line[BUFF_MAX];
	FILE *fp = NULL;
	char *end = NULL;
	char *pos, *sp = NULL, *in[PROCMAP_SZ];
	char dlm[] = "-   :   ";
	uint64_t counter;
	int i;

	snprintf(path, PATH_MAX, "/proc/%u/smaps", pid);

	fp = fopen(path, "r");
	if (fp == NULL) {
		LOG_ERROR("fopen: %s: %s\n", path, strerror(errno));
		return -1;
	}

	procmap = calloc(procmap_max_num, sizeof(*procmap));
	if (procmap == NULL) {
		perror("calloc: procmap");
		goto failed;
	}


#define parse_procmap_stat(name, idx)					\
	if (strstr(line, name)) {					\
		sscanf(line, "%*s%lu", &counter);			\
		procmap[procmap_num - 1].stat.counter[idx] = counter;	\
		continue;						\
	}

	while (fgets(line, BUFF_MAX, fp)) {
		parse_procmap_stat("Size:", SIZE);
		parse_procmap_stat("Rss:", RSS);
		parse_procmap_stat("AnonHugePages:", ANONHUGEPAGES);
		parse_procmap_stat("ShmemPmdMapped:", SHMEMPMDMAPPED);
		parse_procmap_stat("FilePmdMapped:", FILEPMDMAPPED);

		if (strstr(line, "VmFlags:")) {
			strncpy(procmap[procmap_num - 1].stat.vmflags,
				line + strlen("VmFlags: "), VMFLAGS_MAX);
			continue;
		}

		/* Split line into fields */
		pos = line;
		for (i = 0; i < PROCMAP_SZ; i++) {
			in[i] = strtok_r(pos, &dlm[i], &sp);
			if (in[i] == NULL)
				break;
			pos = NULL;
		}

		/* Check this line is procmap item header */
		if (i != PROCMAP_SZ)
			continue;

		/* Convert/Copy each field as needed */
		procmap[procmap_num].va_start = strtoull(in[0], &end, 16);
		if ((*in[0] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		procmap[procmap_num].va_end = strtoull(in[1], &end, 16);
		if ((*in[1] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		procmap[procmap_num].pgoff = strtoull(in[3], &end, 16);
		if ((*in[3] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		procmap[procmap_num].maj = strtoul(in[4], &end, 16);
		if ((*in[4] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		procmap[procmap_num].min = strtoul(in[5], &end, 16);
		if ((*in[5] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		procmap[procmap_num].ino = strtoul(in[6], &end, 16);
		if ((*in[6] == '\0') || (end == NULL) || (*end != '\0') ||
				(errno != 0))
			goto failed;

		memcpy(&procmap[procmap_num].prot, in[2], PROT_SZ);
		memcpy(&procmap[procmap_num].fname, in[7], PATH_MAX);

		if (++procmap_num == procmap_max_num) {
			void *new_procmap;

			procmap_max_num *= 2;
			new_procmap = realloc(procmap, sizeof(*procmap) *
							procmap_max_num);
			if (new_procmap == NULL) {
				perror("realloc: procmap");
				goto failed;
			}
			procmap = new_procmap;
		}
	}

	*p_procmap = procmap;
	if (fp)
		fclose(fp);
	return procmap_num;

failed:
	if (fp)
		fclose(fp);
	if (procmap)
		free(procmap);
	return -1;
}

/*
 * Routines of kcore, i.e., /proc/kcore
 */
uintptr_t lookup_kernel_symbol(const char *symbol_name)
{
	const char *kallsyms_file = "/proc/kallsyms";
	FILE *fp;
	char line[BUFF_MAX];
	char *pos;
	uintptr_t addr = -1UL;

	fp = fopen(kallsyms_file, "r");
	if (fp == NULL) {
		perror("fopen: /proc/kallsyms");
		return -1;
	}

	while (fgets(line, BUFF_MAX, fp)) {
		if ((pos = strstr(line, symbol_name)) == NULL)
			continue;

		/* Remove trailing newline */
		line[strcspn(line, "\n")] = '\0';

		/* Exact match */
		if (pos == line || !isspace(*(pos - 1)))
			continue;
		if (!strcmp(pos, symbol_name)) {
			addr = strtoul(line, NULL, 16);
			break;
		}
	}

	if (addr == -1UL)
		LOG_ERROR("failed to lookup symbol: %s\n", symbol_name);

	fclose(fp);
	return addr;
}

static int kcore_elf_init(void)
{
	Elf64_Ehdr *elf64;
	Elf64_Phdr *load64;
	Elf64_Phdr *notes64;
	char eheader[MAX_KCORE_ELF_HEADER_SIZE];
	size_t load_size, notes_size;

	if (read(kcore_fd, eheader, MAX_KCORE_ELF_HEADER_SIZE) !=
			MAX_KCORE_ELF_HEADER_SIZE) {
		perror("read: /proc/kcore ELF header");
		return -1;
	}

	elf64 = (Elf64_Ehdr *)&eheader[0];
	notes64 = (Elf64_Phdr *)&eheader[sizeof(Elf64_Ehdr)];
	load64 = (Elf64_Phdr *)&eheader[sizeof(Elf64_Ehdr) +
					sizeof(Elf64_Phdr)];

	pkd->segments = elf64->e_phnum - 1;

	notes_size = load_size = 0;
	if (notes64->p_type == PT_NOTE)
		notes_size = notes64->p_offset + notes64->p_filesz;
	if (notes64->p_type == PT_LOAD)
		load_size = (unsigned long)(load64+(elf64->e_phnum)) -
				(unsigned long)elf64;

	pkd->header_size = MAX(notes_size, load_size);
	if (!pkd->header_size)
		pkd->header_size = MAX_KCORE_ELF_HEADER_SIZE;

	if ((pkd->elf_header = (char *)malloc(pkd->header_size)) == NULL) {
		perror("malloc: /proc/kcore ELF header");
		return -1;
	}

	memcpy(&pkd->elf_header[0], &eheader[0], pkd->header_size);
	pkd->notes64 = (Elf64_Phdr *)&pkd->elf_header[sizeof(Elf64_Ehdr)];
	pkd->load64 = (Elf64_Phdr *)&pkd->elf_header[sizeof(Elf64_Ehdr) +
						     sizeof(Elf64_Phdr)];

	return 0;
}

static int kcore_init(void)
{
	unsigned long vmemmap_symbol_addr;
	unsigned long page_offset_symbol_addr;
	int size;

	if ((kcore_fd = open("/proc/kcore", O_RDONLY)) < 0) {
		perror("open: /proc/kcore");
		return -1;
	}

	if (kcore_elf_init())
		goto failed;

	vmemmap_symbol_addr = lookup_kernel_symbol("vmemmap_base");
	if (vmemmap_symbol_addr == -1) {
		LOG_WARN("continue to use default vmemmap_base: 0x%lx\n",
				vmemmap_base);
	} else {
		size = kcore_readmem(vmemmap_symbol_addr, &vmemmap_base, 8);
		if (size < 8)
			goto failed;
	}

	page_offset_symbol_addr = lookup_kernel_symbol("page_offset_base");
	if (page_offset_symbol_addr == -1) {
		LOG_WARN("continue to use default page_offset_base: 0x%lx\n",
				page_offset_base);
	} else {
		size = kcore_readmem(page_offset_symbol_addr, &page_offset_base, 8);
		if (size < 8)
			goto failed;
	}

	return 0;

failed:
	close(kcore_fd);
	return -1;
}

/*
 * We may accidentally access invalid pfns on some kernels
 * like 4.9, due to known bugs. Just skip it.
 */
ssize_t kcore_readmem(unsigned long kvaddr, void *buf, ssize_t size)
{
	Elf64_Phdr *lp64;
	unsigned long offset = -1UL;
	ssize_t read_size;
	int i;

	for (i = 0; i < pkd->segments; i++) {
		lp64 = pkd->load64 + i;
		if ((kvaddr >= lp64->p_vaddr) &&
			(kvaddr < (lp64->p_vaddr + lp64->p_memsz))) {
			offset = (off_t)(kvaddr - lp64->p_vaddr) +
					(off_t)lp64->p_offset;
			break;
		}
	}
	if (i == pkd->segments) {
		for (i = 0; i < pkd->segments; i++) {
			lp64 = pkd->load64 + i;
			LOG_DEBUG("%2d: [0x%lx, 0x%lx)\n", i, lp64->p_vaddr,
					lp64->p_vaddr + lp64->p_memsz);
		}
		LOG_ERROR("invalid kvaddr 0x%lx\n", kvaddr);
		goto failed;
	}

	if (lseek(kcore_fd, offset, SEEK_SET) < 0) {
		perror("lseek: /proc/kcore");
		goto failed;
	}

	read_size = read(kcore_fd, buf, size);
	if (read_size < size) {
		perror("read: /proc/kcore");
		goto failed;
	}

	return read_size;

failed:
	return -1;
}

static void kcore_exit(void)
{
	if (pkd->elf_header)
		free(pkd->elf_header);
	if (kcore_fd > 0)
		close(kcore_fd);
}

/*
 * Routines of buddy_info
 */
static struct buddy_info *buddy_info_create(uint64_t phy_mem_in_bytes)
{
	struct buddy_info *buddy_info;

	buddy_info = calloc(1, sizeof(*buddy_info));
	if (buddy_info == NULL) {
		perror("calloc: buddy_info");
		return NULL;
	}
	buddy_info->bitmap_size = ROUND_UP(phy_mem_in_bytes, PAGE_SIZE);
	buddy_info->mmap_size = ROUND_UP(buddy_info->bitmap_size, 8);

	/* Mmap pages are lazy allocated, and zeroed when fault */
	buddy_info->bitmap = mmap(NULL, buddy_info->mmap_size,
					PROT_READ | PROT_WRITE,
					MAP_PRIVATE | MAP_ANONYMOUS ,
					-1, 0);
	if (buddy_info->bitmap == MAP_FAILED) {
		perror("mmap: buddy_info->bitmap");
		free(buddy_info);
		return NULL;
	}
	LOG_DEBUG("pagemap [%p, %p)\n", buddy_info->bitmap,
			(void *)((uintptr_t)buddy_info->bitmap +
					buddy_info->mmap_size));

	buddy_info->phy_mem_in_bytes = phy_mem_in_bytes;
	return buddy_info;
}

static void buddy_info_destroy(struct buddy_info *buddy_info)
{
	munmap(buddy_info->bitmap, buddy_info->mmap_size);
	free(buddy_info);
}

static void buddy_info_set_bit(struct buddy_info *buddy_info, uint64_t pos)
{
	set_bit(pos, buddy_info->bitmap);
}

bool buddy_info_test_bit(struct buddy_info *buddy_info, uint64_t pos)
{
	return test_bit(pos, buddy_info->bitmap);
}

/*
 * Routines of environment setup
 */
static int parse_numa_info(void)
{
	const char *zoneinfo_file = "/proc/zoneinfo";
	FILE *fp = NULL;
	char line[BUFF_MAX];
	uint64_t start_pfn;
	int node = -1, last_node = -1;

	fp = fopen(zoneinfo_file, "r");
	if (fp == NULL) {
		perror("fopen: /proc/zoneinfo");
		return -1;
	}

	while (fgets(line, BUFF_MAX, fp)) {
		/* "Node 0, zone      DMA" */
		if (sscanf(line, "Node %d, %*s\n", &node) == 1)
			continue;

		/* "  start_pfn:           1" */
		if (sscanf(line, "  start_pfn: %"SCNu64"\n", &start_pfn) == 1) {
			if (node != last_node) {
				numa_info[node].exist = 1;
				numa_info[node].start_pfn = start_pfn;
				LOG_DEBUG("node: %d, start_pfn: %lu\n", node,
								start_pfn);
				if (node > nr_numa_node)
					nr_numa_node = node;
				last_node = node;
			}
			continue;
		}
	}

	fclose(fp);
	return 0;
}

int pfn_to_node(unsigned long pfn)
{
	int node;

	for (node = 0; node <= nr_numa_node; node++) {
		if (!numa_info[node].exist)
			break;

		if (pfn < numa_info[node].start_pfn)
			break;
	}

	return node - 1;
}

static uint64_t get_max_phy_addr()
{
	const char *iomem_file = "/proc/iomem";
	FILE *fp = NULL;
	char line[BUFF_MAX], *pos, *end = NULL;
	uint64_t max_phy_addr = 0;

	fp = fopen(iomem_file, "r");
	if (fp == NULL) {
		perror("fopen: /proc/iomem");
		return -1;
	}

	while (fgets(line, BUFF_MAX, fp)) {
		if (strstr(line, "System RAM") == NULL)
			continue;

		pos = strchr(line, '-');
		if (pos == NULL)
			break;
		pos++;

		max_phy_addr = strtoull(pos, &end, 16);
		if (end == NULL || errno != 0) {
			perror("strtoull: max_phy_addr");
			max_phy_addr = 0;
			break;
		}
	}

	fclose(fp);
	return max_phy_addr;
}

static char *get_cmdline(pid_t pid)
{
	char path[PATH_MAX];
	FILE *fp;
	char *cmdline;

	snprintf(path, PATH_MAX, "/proc/%u/cmdline", pid);
	fp = fopen(path, "r");
	if (fp == NULL) {
		LOG_ERROR("fopen: %s: %s\n", path, strerror(errno));
		return NULL;
	}

	cmdline = (char *)calloc(1, PATH_MAX);
	if (cmdline == NULL) {
		perror("calloc: cmdline");
		fclose(fp);
		return NULL;
	}

	if (fread(cmdline, 1, PATH_MAX, fp) == 0)
		snprintf(cmdline, PATH_MAX, "unknown");

	fclose(fp);
	return cmdline;
}

int pid_parse(const char *arg, pid_t **p_pids)
{
	pid_t *pids = NULL;
	unsigned long pid;
	int pid_max_num = 8, pid_num = 0;
	const char *pos = arg;
	char *end;

	pids = calloc(pid_max_num, sizeof(*pids));
	if (pids == NULL) {
		perror("calloc: pids");
		return -1;
	}

	while (1) {
		pid = strtoul(pos, &end, 0);
		if (pid == ULONG_MAX) {
			LOG_ERROR("pid out of range: %s\n", arg);
			goto failed;
		}

		pids[pid_num++] = (pid_t)pid;

		if (*end == '\0')
			break;
		if (*end != ',') {
			LOG_ERROR("pid invalid format: %s\n", arg);
			goto failed;
		}
		pos = end + 1;

		if (pid_num == pid_max_num) {
			void *new_pids = NULL;

			pid_max_num *= 2;
			pids = realloc(pids, sizeof(*pids) * pid_max_num);
			if (new_pids == NULL) {
				perror("realloc: pids");
				goto failed;
			}
			pids = new_pids;
		}
	}

	*p_pids = pids;
	return pid_num;

failed:
	if (pids)
		free(pids);
	return -1;
}

static int setup(void)
{
	g_max_phy_addr = get_max_phy_addr();
	if (g_max_phy_addr == 0ULL) {
		LOG_ERROR("failed to get max physical address\n");
		return -1;
	}
	LOG_DEBUG("max physical address = %#lx\n", g_max_phy_addr);

	if (parse_numa_info()) {
		LOG_ERROR("failed to parse numa info\n");
		return -1;
	}

	kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
	if (kpageflags_fd < 0) {
		perror("open: /proc/kpageflags");
		return -1;
	}

	if (kcore_init() < 0) {
		LOG_ERROR("failed to init kcore\n");
		return -1;
	}

	return 0;
}

static void cleanup(void)
{
	if (kpageflags_fd > 0)
		close(kpageflags_fd);
	kcore_exit();
}

/*
 * Routines of scan
 */
static int scan_step(uint64_t va_start, uint64_t va_end, uint64_t *va_idx)
{
	uint64_t old_idx = *va_idx, new_idx;

	new_idx = (old_idx + HUGE_SIZE) & ~(HUGE_SIZE - 1);
	if (new_idx > va_end)
		new_idx = va_end;

	*va_idx = new_idx;
	return (new_idx - old_idx) / PAGE_SIZE;
}

static void scan_memory_region(struct buddy_info *buddy_info, int pagemap_fd,
				uint64_t va_start, uint64_t va_end)
{
	off64_t offset;
	uint64_t raw_pfns[HUGE_PAGE_NR], va_idx = va_start;
	uint64_t curr_pfn;
	int target_pfn_num, scan_pfn_num;
	int idx;

	offset = (va_start >> PAGE_SHIT) * sizeof(uint64_t);

	if (lseek64(pagemap_fd, offset, SEEK_SET) < 0) {
		LOG_ERROR("lseek64: %#lx: %s\n", va_start, strerror(errno));
		return;
	}
	LOG_DEBUG("scan memory region: [%p, %p)\n", (void *)va_start,
							(void *)va_end);

	while ((target_pfn_num = scan_step(va_start, va_end, &va_idx)) != 0) {
		scan_pfn_num = read(pagemap_fd, raw_pfns,
					sizeof(*raw_pfns) * target_pfn_num);
		if (scan_pfn_num == -1) {
			perror("read: pagemap");
			break;
		} else if (scan_pfn_num == 0)
			break;

		scan_pfn_num /= sizeof(*raw_pfns);
		if (scan_pfn_num != target_pfn_num)
			LOG_WARN("scan pfn num (%d) != target pfn num (%d)\n",
					scan_pfn_num, target_pfn_num);

		for (idx = 0; idx < scan_pfn_num; idx++) {
			if (opt.zero_subpages)
				scan_zero_subpages_in_base(raw_pfns[idx], idx,
								scan_pfn_num);

			if (!(raw_pfns[idx] & (1UL << PAGEMAP_PRESENT)))
				continue;

			curr_pfn = raw_pfns[idx] & PAGEMAP_PFN_MASK;
			buddy_info_set_bit(buddy_info, curr_pfn);
		}
	}
}

static struct buddy_info *scan_pids(pid_t *pids, int pid_num)
{
	char path[PATH_MAX], *cmdline;
	struct buddy_info *buddy_info;
	struct procmap *procmap;
	int procmap_num, procmap_idx, pid_idx;
	int pagemap_fd = -1;
	pid_t pid;

	buddy_info = buddy_info_create(g_max_phy_addr);
	if (buddy_info == NULL)
		return NULL;

	LOG_INFO("pid\tcmdline\n");
	for (pid_idx = 0; pid_idx < pid_num; pid_idx++) {
		pid = pids[pid_idx];

		cmdline = get_cmdline(pids[pid_idx]);
		LOG_INFO("%d\t%s\n", pid, cmdline ? : "null");
		if (cmdline)
			free(cmdline);

		snprintf(path, PATH_MAX, "/proc/%u/pagemap", pid);
		pagemap_fd = open(path, O_RDONLY);
		if (pagemap_fd == -1) {
			LOG_ERROR("open: %s: %s\n", path, strerror(errno));
			continue;
		}

		/*
		 * There exist a race bettween scanning memory region and
		 * pagemap.  They are not atomic, but doesn't matter.
		 */
		procmap = NULL;
		procmap_num = get_memory_map(pid, &procmap);
		if (procmap_num <= 0 || procmap == NULL) {
			close(pagemap_fd);
			if (procmap)
				free(procmap);
			continue;
		}

		if (opt.exec_vma)
			scan_exec_vma(procmap, procmap_num);

		for (procmap_idx = 0; procmap_idx < procmap_num; procmap_idx++) {
			/* Skip vsyscall */
			if (strstr(procmap[procmap_idx].fname, "[vsyscall]"))
				continue;

			scan_memory_region(buddy_info, pagemap_fd,
					procmap[procmap_idx].va_start,
					procmap[procmap_idx].va_end);
		}

		close(pagemap_fd);
		free(procmap);
	}

	LOG_INFO("\n");
	return buddy_info;
}

static void show_usage(const char *name)
{
	LOG_INFO("Usage: %s [OPTIONS]\n"
		 "\n"
		 "  -h, --help           display this help and exit\n"
		 "\n"
		 "Supported options:\n"
		 "  -p, --pid            process IDs (comma sperated)\n"
		 "  -f, --fragment       scan page's external fragmentation to estimate compaction function\n"
		 "  -m, --movability     scan page's movability to estimate compaction function\n"
		 "  -z, --zero_subpages  scan zero subpages wrt base pages and THP to estimate memory bloating\n"
		 "  -s, --slab           scan fine-grained slab external fragments\n"
		 "\n"
		 , name);
	scan_movability_help();
}

int main(int argc, char *argv[])
{
	struct buddy_info *buddy_info = NULL;
	int ch, ret;

	const char *sopt = "hp:fmzs:e";
	const struct option lopt[] = {
		{"help", 0, NULL, 'h'},
		{"pid", 1, NULL, 'p'},
		{"fragment", 0, NULL, 'f'},
		{"moability", 0, NULL, 'm'},
		{"zero_subpages", 0, NULL, 'z'},
		{"slab", 0, NULL, 's'},
		{"exec_vma", 0, NULL, 'e'},
		{ NULL, 0, NULL, 0 }
	};

	while ((ch = getopt_long(argc, argv, sopt, lopt, &optind)) != -1) {
		switch (ch) {
		case 'p':
			opt.pid_num = pid_parse(optarg, &opt.pids);
			if (opt.pids == NULL || opt.pid_num == 0)
				return -1;
			break;
		case 'f':
			opt.fragment = true;
			break;
		case 'm':
			opt.movability = true;
			break;
		case 'z':
			opt.zero_subpages = true;
			break;
		case 's':
			opt.slabs = strdup(optarg);
			break;
		case 'e':
			opt.exec_vma = true;
			break;
		case 'h':
			show_usage(argv[0]);
			return 0;
		case '?':
			LOG_ERROR("try `%s --help' for more information\n",
					argv[0]);
			return -1;
		}
	}

	if (getuid()) {
		LOG_ERROR("must be root\n");
		ret = -EPERM;
		goto out;
	}

	nice(20);

	ret = setup();
	if (ret != 0) {
		LOG_ERROR("failed to setup\n");
		goto out;
	}

	if (opt.pids != NULL && opt.pid_num != 0)
		buddy_info = scan_pids(opt.pids, opt.pid_num);
	if (opt.fragment)
		scan_fragment(buddy_info);
	if (opt.movability)
		scan_movability(buddy_info);
	if (opt.zero_subpages)
		scan_zero_subpages(buddy_info);
	if (opt.slabs)
		scan_slabs(opt.slabs);

out:
	if (buddy_info)
		buddy_info_destroy(buddy_info);
	if (opt.slabs)
		free(opt.slabs);
	if (opt.pids)
		free(opt.pids);
	cleanup();

	return ret;
}
