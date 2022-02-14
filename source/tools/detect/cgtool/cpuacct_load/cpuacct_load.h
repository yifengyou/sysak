#ifndef __CGTRACE_H
#define __CGTRACE_H

#define AVENRUN_MAX 10

struct cpuacct_load {
	unsigned long run[AVENRUN_MAX][3];
	unsigned int avenrun_index;
	unsigned int avenrun_n;
	unsigned int knid;
};

/* cal load from kernel */
#define FSHIFT          11              /* nr of bits of precision */
#define FIXED_1         (1<<FSHIFT)     /* 1.0 as fixed-point */
#define LOAD_INT(x) ((x) >> FSHIFT)
#define LOAD_FRAC(x) LOAD_INT(((x) & (FIXED_1-1)) * 100)

static unsigned long cal_load_int(unsigned long avenrun)
{
	unsigned long load_tmp = (avenrun + FIXED_1/200) << 0;
	return LOAD_INT(load_tmp);
}

static unsigned long cal_load_frac(unsigned long avenrun)
{
	unsigned long load_tmp = (avenrun + FIXED_1/200) << 0;
	return LOAD_FRAC(load_tmp);
}
#endif
