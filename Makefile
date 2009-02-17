CC       = gcc
CFLAGS   = -g -Wall -O2

all: gmd

gmd: gmd.c
	$(CC) $(CFLAGS) $< -lx86emu -o $@

clean:
	rm -f *~ *.o gmd
