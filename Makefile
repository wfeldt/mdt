CC       = gcc
CFLAGS   = -g -Wall -O2

all: mdt

mdt: mdt.c
	$(CC) $(CFLAGS) $< -lx86emu -o $@

clean:
	rm -f *~ *.o mdt
