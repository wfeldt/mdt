CC          = gcc
CFLAGS      = -g -O2 -Wall
CFLAGS_BARE = -O2 -Wall -Wno-pointer-sign -fomit-frame-pointer -m32 \
              -fno-pie -fno-align-functions -fno-align-labels -fno-align-jumps -fno-align-loops \
              -fno-builtin -nostdinc -I . 
ASMFLAGS    = -O99 -felf
BINDIR      = /usr/bin

all: mdt mdt.com mdt.bin

cds: mdt.iso mdt_dos.iso

libio_dos.o: libio.asm
	nasm $(ASMFLAGS) -o $@ -l $*.lst $<

libio_bin.o: libio.asm
	nasm -dBIN $(ASMFLAGS) -o $@ -l $*.lst $<

mdt.o: mdt_bare.c libio.h
	$(CC) -g $(CFLAGS_BARE) -c -o $@ $<

mdt.com: mdt.o libio_dos.o
	ld -Tcom.ld -o $@ $^

mdt.bin: mdt.o libio_bin.o
	ld -Tbin.ld -o $@ $^

mdt_dos.iso: mdt.com
	# fat12: type 0x01, freedos_boot.fat12
	# fat16: type 0x0e, freedos_boot.fat16
	./hdimage \
	  --size 1000 --chs 0 4 63 --type 0x01 \
	  --mbr /usr/share/syslinux/mbr.bin \
	  --mkfs fat --label MONITOR --boot-block dosfiles/freedos_boot.fat12 \
	  mdt.img
	mcopy -i 'mdt.img|partition=1' \
	  dosfiles/{kernel.sys,config.sys,autoexec.bat,command.com} $< \
	  ::
	rm -rf tmp
	mkdir -p tmp
	mv mdt.img tmp
	cp dosfiles/isolinux.cfg tmp
	cp /usr/share/syslinux/memdisk tmp
	cp /usr/share/syslinux/isolinux.bin tmp
	mkisofs -o $@ -f \
	  -no-emul-boot -boot-load-size 4 -boot-info-table -b isolinux.bin \
	  -hide boot.catalog \
	  tmp

mdt.iso: mdt.bin
	rm -rf tmp
	mkdir tmp
	cp $< tmp
	mkisofs -o $@ -f -no-emul-boot -hide boot.catalog -b $< tmp

mdt: mdt.c
	$(CC) $(CFLAGS) $< -lx86emu -o $@

install: mdt.iso mdt_dos.iso
	install -d -m 755 $(DESTDIR)/usr/share/mdt
	install -m 644 $^ $(DESTDIR)/usr/share/mdt
	install -m 755 -D mdt $(DESTDIR)$(BINDIR)/mdt

clean:
	@rm -rf mdt mdt.com mdt.bin *~ *.iso *.lst *.map *.o *.s *.i tmp
