#ifndef _ASM_GENERIC_BITOPS_H
#define _ASM_GENERIC_BITOPS_H

#include <stdbool.h>

#define BITS_PER_LONG		64
#define BIT_MASK(nr)		(1UL << ((nr) % BITS_PER_LONG))
#define BIT_WORD(nr)		((nr) / BITS_PER_LONG)

/* Undefined if no bit exists, so code should check against 0 first. */
static inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

/* Undefined if no zero exists, so code should check against ~0UL first. */
#define ffz(x)  __ffs(~(x))

/* Undefined if no set bit exists, so code should check against 0 first. */
static inline unsigned long __fls(unsigned long word)
{
	return (sizeof(word) * 8) - 1 - __builtin_clzl(word);
}

static inline int fls(int x)
{
	return x ? sizeof(x) * 8 - __builtin_clz(x) : 0;
}

static inline int fls64(unsigned long long x)
{
	if (x == 0)
		return 0;
	return __fls(x) + 1;
}

/* This function is non-atomic and may be reordered. */
static inline void __set_bit(long nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p  |= mask;
}

static inline void set_bit(long nr, volatile unsigned long *addr)
{
	__set_bit(nr, addr);
}

static inline bool __test_bit(long nr, volatile const unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (BITS_PER_LONG-1)));
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
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	*p &= ~mask;
}

static inline void clear_bit(long nr, volatile unsigned long *addr)
{
	__clear_bit(nr, addr);
}
#endif /* _ASM_GENERIC_BITOPS_H */
