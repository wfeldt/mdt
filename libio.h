/*
 *
 * file.h	include file for libio
 *
 * Copyright (c) 2008 Steffen Winterfeldt.
 *
 * For details see file COPYING.
 *
 */

#ifndef _LIBIO_H
#define _LIBIO_H

asm(".code16gcc\n");

#define main _main

typedef struct {
  unsigned eax, ebx, ecx, edx, esi, edi, ebp, eflags;
} x86regs_t;

int _main(void);
void printf(char *format, ...) __attribute__ ((format (printf, 1, 2)));
int getchar(void);
void clrscr(void);
void *memcpy(void *dest, const void *src, int n);
void *memset(void *dest, int c, int n);
void x86int(unsigned intr, x86regs_t *regs);

#endif	/* _LIBIO_H */
