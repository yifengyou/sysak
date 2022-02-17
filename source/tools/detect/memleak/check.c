#include<stdlib.h>
#include<stdio.h>
#include<string.h>

#include "user_api.h"

#define MEMINFO "/proc/meminfo"
#define LEN_128 (128)
#define LEN_4096 (4096)


#define hugepath "/sys/kernel/mm/hugepages/hugepages-1048576kB/nr_hugepages"
static int read_hugepage1G(void)
{
    FILE *fp;
    char line[LEN_128];
    unsigned long nr =0; 

    fp = fopen(hugepath, "r");
    if (fp == NULL)
        return 0;

    if (fgets(line, 128,fp) == NULL) {
        fclose(fp);
        return 0;
    }   

    sscanf(line, "%lu", &nr);
    fclose(fp);
    return nr;
}


int read_meminfo(struct meminfo *mem)
{
    FILE             *fp;
    char              line[LEN_128];
    char              buf[LEN_4096];
    struct meminfo st_mem;
    unsigned long anonPage = 0;
    unsigned long hugeSize = 0;
    unsigned long hugeTotal = 0;

    memset(buf, 0, LEN_4096);
    memset(&st_mem, 0, sizeof(st_mem));
    if ((fp = fopen(MEMINFO, "r")) == NULL) {
        return 0;
    }

    while (fgets(line, 128, fp) != NULL) {

        if (!strncmp(line, "MemTotal:", 9)) {
            /* Read the total amount of memory in kB */
            sscanf(line + 9, "%lu", &st_mem.tlmkb);
        }
        else if (!strncmp(line, "MemFree:", 8)) {
            /* Read the amount of free memory in kB */
            sscanf(line + 8, "%lu", &st_mem.frmkb);
        }
        else if (!strncmp(line, "Buffers:", 8)) {
            /* Read the amount of buffered memory in kB */
            sscanf(line + 8, "%lu", &st_mem.bufkb);
        }
        else if (!strncmp(line, "SUnreclaim:", 11)) {
            /* Read the amount of slab memory in kB */
            sscanf(line + 11, "%lu", &st_mem.uslabkb);
        }
        else if (!strncmp(line, "Active:", 7)) {
            /* Read the amount of Active memory in kB */
            sscanf(line + 7, "%lu", &st_mem.acmkb);
        }
        else if (!strncmp(line, "Inactive:", 9)) {
            /* Read the amount of Inactive memory in kB */
            sscanf(line + 9, "%lu", &st_mem.iamkb);
        }
        else if (!strncmp(line, "Slab:", 5)) {
            /* Read the amount of Slab memory in kB */
            sscanf(line + 5, "%lu", &st_mem.slmkb);
        }
        else if (!strncmp(line, "HugePages_Total:", 16)) {
            /* Read the amount of commited memory in kB */
            sscanf(line + 16, "%lu", &hugeTotal);
        }
        else if (!strncmp(line, "Hugepagesize:", 13)) {
            /* Read the amount of commited memory in kB */
            sscanf(line + 13, "%lu", &hugeSize);
        }
        else if (!strncmp(line, "Mlocked:", 8)) {
            /* Read the amount of commited memory in kB */
            sscanf(line + 8, "%lu", &st_mem.lock);
        }
    }
    st_mem.huge1G = read_hugepage1G()*1024*1024;
    if (hugeSize == 2048)
        st_mem.huge2M = hugeTotal * hugeSize;

    st_mem.kernel = st_mem.tlmkb - st_mem.frmkb - st_mem.acmkb - st_mem.iamkb - st_mem.lock -\
                st_mem.bufkb - st_mem.slmkb - st_mem.huge2M - st_mem.huge1G;

    if (st_mem.kernel < 0)
        st_mem.kernel = (1 << 10);
    *mem = st_mem;
    return 0;
}

int test_main(void)
{
    struct meminfo mem;
    read_meminfo(&mem);
    printf(" kernel used %dM\n", mem.kernel/1024);
    return 0; 
}
