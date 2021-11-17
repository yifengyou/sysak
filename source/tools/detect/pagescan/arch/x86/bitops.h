#ifndef _ASM_X86_BITOPS_H
#define _ASM_X86_BITOPS_H

#include <stdbool.h>

#define BITS_PER_LONG		64
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

/* Undefined if no bit exists, so code should check against 0 first. */
static inline unsigned long __ffs(unsigned long word)
{
	__asm__ volatile("rep; bsf %1,%0"
			: "=r" (word)
			: "rm" (word));
	return word;
}

/* Undefined if no zero exists, so code should check against ~0UL first. */
static inline unsigned long ffz(unsigned long word)
{
	__asm__ volatile("rep; bsf %1,%0"
			: "=r" (word)
			: "r" (~word));
	return word;
}

/* Undefined if no set bit exists, so code should check against 0 first. */
static inline unsigned long __fls(unsigned long word)
{
	__asm__ volatile("bsr %1,%0"
			: "=r" (word)
			: "rm" (word));
	return word;
}

static inline int fls(int x)
{
	int r;
	__asm__ volatile("bsrl %1,%0"
			: "=r" (r)
			: "rm" (x), "0" (-1));
	return r + 1;
}

static inline int fls64(unsigned long long x)
{
	int bitpos = -1;
	__asm__ volatile("bsrq %1,%q0"
			: "+r" (bitpos)
			: "rm" (x));
	return bitpos + 1;
}

/* This function is non-atomic and may be reordered. */
static inline void __set_bit(long nr, volatile unsigned long *addr)
{
	__asm__ volatile("btsq %1,%0"
			:
			: "m" (*(volatile long *) (addr)), "Ir" (nr)
			: "memory");
}

static inline void set_bit(long nr, volatile unsigned long *addr)
{
	__set_bit(nr, addr);
}

static inline bool __test_bit(long nr, volatile const unsigned long *addr)
{
	bool oldbit;

	asm volatile("btq %2,%1\n\t"
			"setc %0"
			: "=qm" (oldbit)
			: "m" (*(unsigned long *)addr), "Ir" (nr));

	return oldbit;
}

static inline bool test_bit(long nr, volatile const unsigned long *addr)
{
	return __test_bit(nr, addr);
}

/*
 * This function is non-atomic and implies release semantics before the memory
 * operation.
 */
static inline void __clear_bit(long nr, volatile unsigned long *addr)
{
	__asm__ volatile("btrq %1,%0"
			:
			: "m" (*(volatile long *) (addr)), "Ir" (nr)
			: "memory");
}

static inline void clear_bit(long nr, volatile unsigned long *addr)
{
	__clear_bit(nr, addr);
}
#endif /* _ASM_X86_BITOPS_H */
