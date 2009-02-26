#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>
#include <inttypes.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/io.h>
#include <linux/fs.h>	/* BLKGETSIZE64 */
#include <x86emu.h>

typedef struct {
  x86emu_t *emu;

  unsigned kbd_cnt;
  unsigned key;

  unsigned memsize;	// in MB

  unsigned a20:1;

  struct {
    int (* iv_funcs[0x100])(void);
  } bios;

} vm_t;


void lprintf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void flush_log(char *buf, unsigned size);

void help(void);
u8 deb_inb(u16 addr);
u16 deb_inw(u16 addr);
u32 deb_inl(u16 addr);
void deb_outb(u16 addr, u8 val);
void deb_outw(u16 addr, u16 val);
void deb_outl(u16 addr, u32 val);
int check_ip(void);
vm_t *vm_new(void);
void vm_free(vm_t *vm);
int vm_run(vm_t *vm);
int do_int(u8 num, unsigned type);
void prepare_bios(vm_t *vm);
int map_memory(x86emu_mem_t *mem, off_t start, unsigned size);


struct option options[] = {
  { "help",       0, NULL, 'h'  },
  { "verbose",    0, NULL, 'v'  },
  { "show",       1, NULL, 1005 },
  { "no-show",    1, NULL, 1006 },
  { "port",       1, NULL, 1007 },
  { "raw",        0, NULL, 1008 },
  { "bios",       1, NULL, 1009 },
  { "bios-entry", 1, NULL, 1010 },
  { }
};

struct {
  unsigned verbose;
  unsigned port;

  struct {
    unsigned code:1;
    unsigned regs:1;
    unsigned data:1;
    unsigned io:1;
    unsigned intr:1;
    unsigned acc:1;
    unsigned rawptable:1;
    unsigned dump:1;
    unsigned dumpmem:1;
    unsigned dumpattr:1;
    unsigned dumpregs:1;
  } show;

  unsigned raw:1;
  char *bios;
  unsigned bios_entry;
} opt;


FILE *log_file = NULL;

int main(int argc, char **argv)
{
  int i, err;
  char *s, *t;
  unsigned u;
  vm_t *vm;

  log_file = stdout;

  opterr = 0;

  while((i = getopt_long(argc, argv, "hv", options, NULL)) != -1) {
    err = 0;

    switch(i) {
      case 'v':
        opt.verbose++;
        break;

      case 1005:
      case 1006:
        s = optarg;
        u = i == 1005 ? 1 : 0;
        while((t = strsep(&s, ","))) {
          if(!strcmp(t, "code")) opt.show.code = u;
          else if(!strcmp(t, "regs")) opt.show.regs = u;
          else if(!strcmp(t, "data")) opt.show.data = u;
          else if(!strcmp(t, "io")) opt.show.io = u;
          else if(!strcmp(t, "intr")) opt.show.intr = u;
          else if(!strcmp(t, "acc")) opt.show.acc = u;
          else if(!strcmp(t, "dump")) opt.show.dump = u;
          else if(!strcmp(t, "dump.mem")) opt.show.dumpmem = u;
          else if(!strcmp(t, "dump.attr")) opt.show.dumpattr = u;
          else if(!strcmp(t, "dump.regs")) opt.show.dumpregs = u;
          else err = 5;
        }
        break;

      case 1007:
        opt.port = strtoul(optarg, NULL, 0);
        break;

      case 1008:
        opt.raw = 1;
        break;

      case 1009:
        opt.bios = optarg;
        break;

      case 1010:
        opt.bios_entry = strtoul(optarg, NULL, 0);
        break;

      default:
        help();
        return i == 'h' ? 0 : 1;
    }
  }

  fflush(stdout);

  vm = vm_new();

  prepare_bios(vm);

  vm_run(vm);

  return 0;
}


void lprintf(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  if(log_file) vfprintf(log_file, format, args);
  va_end(args);
}


void flush_log(char *buf, unsigned size)
{
  if(!buf || !size || !log_file) return;

  fwrite(buf, size, 1, log_file);
}


void help()
{
  fprintf(stderr,
    "Get Monitor Data\nusage: gmd options\n"
    "  --show LIST\n"
    "      things to log\n"
    "      LIST is a comma-separated list of code, regs, data, io, intr, acc,\n"
    "      dump, dump.mem, dump.attr, dump.regs\n"
    "  --no-show LIST\n"
    "      things not to log (see --show)\n"
    "  --raw\n"
    "      print DDC data in binary form to stderr\n"
    "  --verbose\n"
    "      log more (can be given more than once for even more logs)\n"
    "  --help\n"
    "      show this text\n"
  );
}


u8 deb_inb(u16 addr)
{
  u8 u;

  u = inb(addr);
//  x86emu_log("# i [%04x] = %02x\n", addr, u);

  return u;
}


u16 deb_inw(u16 addr)
{
  u16 u;

  u = inw(addr);
//  x86emu_log("# i [%04x] = %04x\n", addr, u);

  return u;
}


u32 deb_inl(u16 addr)
{
  u32 u;

  u = inl(addr);
//  x86emu_log("# i [%04x] = %08x\n", addr, u);

  return u;
}


void deb_outb(u16 addr, u8 val)
{
//  x86emu_log("# o [%04x] = %02x\n", addr, val);
  outb(val, addr);
}


void deb_outw(u16 addr, u16 val)
{
//  x86emu_log("# o [%04x] = %04x\n", addr, val);
  outw(val, addr);
}


void deb_outl(u16 addr, u32 val)
{
//  x86emu_log("# o [%04x] = %08x\n", addr, val);
  outl(val, addr);
}


int check_ip()
{
  x86emu_mem_t *mem = x86emu.mem;
  unsigned u, u1, u_m1, u2;
  int abort = 0;

  u = x86emu.x86.R_CS_BASE + x86emu.x86.R_EIP;

  if(vm_read_byte_noerr(mem, u) == 0xeb) {
    u1 = vm_read_byte_noerr(mem, u + 1);
    u_m1 = vm_read_byte_noerr(mem, u - 1);
    if(
      u1 == 0xfe ||
      (u1 == 0xfd && u >= 1 && (u_m1 == 0xfb || u_m1 == 0xfa))
    ) {
      x86emu_log(&x86emu, "* loop detected\n");
      abort = 1;
    }
  }

  if(vm_read_byte_noerr(mem, u) == 0xe9) {
    u1 = vm_read_byte_noerr(mem, u + 1);
    u2 = vm_read_byte_noerr(mem, u + 2);
    if(u1 == 0xfd && u2 == 0xff) {
      x86emu_log(&x86emu, "* loop detected\n");
      abort = 1;
    }
  }

  return abort;
}


int do_int(u8 num, unsigned type)
{
  vm_t *vm = x86emu.private;

  if((type & 0xff) == INTR_TYPE_FAULT) {
    x86emu_stop();

    return 0;
  }

  // no special handling
  return 0;

  if(vm->bios.iv_funcs[num]) return 0;

  x86emu_log(&x86emu, "* unhandled interrupt 0x%02x\n", num);

  return 1;
}


vm_t *vm_new()
{
  vm_t *vm;
  unsigned u;

  vm = calloc(1, sizeof *vm);

  vm->emu = x86emu_new();
  vm->emu->private = vm;

  x86emu_set_log(vm->emu, 200000000, flush_log);

  for(u = 0; u < 0x100; u++) x86emu_set_intr_func(vm->emu, u, do_int);

  x86emu_set_code_check(vm->emu, check_ip);

  return vm;
}


void vm_free(vm_t *vm)
{
  free(vm);
}


int vm_run(vm_t *vm)
{
  int ok = 1, i;

  if(opt.show.regs) vm->emu->log.regs = 1;
  if(opt.show.code) vm->emu->log.code = 1;
  if(opt.show.data) vm->emu->log.data = 1;
  if(opt.show.acc) vm->emu->log.acc = 1;
  if(opt.show.io) vm->emu->log.io = 1;
  if(opt.show.intr) vm->emu->log.intr = 1;

  vm->emu->x86.tsc = 0;
  vm->emu->x86.tsc_max = -1;

  if(vm_read_word(vm->emu->mem, 0x7c00) == 0) return ok;

  iopl(3);

  x86emu_exec(vm->emu);

  iopl(0);

  if(opt.show.dump || opt.show.dumpmem || opt.show.dumpattr || opt.show.dumpregs) {
    i = 0;
    if(opt.show.dump) i |= -1;
    if(opt.show.dumpmem) i |= X86EMU_DUMP_MEM;
    if(opt.show.dumpattr) i |= X86EMU_DUMP_MEM | X86EMU_DUMP_ATTR;
    if(opt.show.dumpregs) i |= X86EMU_DUMP_REGS;
    x86emu_log(vm->emu, "\n- - vm dump - -\n");
    x86emu_dump(vm->emu, i);
  }

  x86emu_clear_log(vm->emu, 1);

  if(vm->emu->mem->invalid_write) ok = 0;

  printf("port = %u, eax = %08x\n", opt.port, vm->emu->x86.R_EAX);

  if(opt.raw) {
    for(i = 0; i < 0x80; i++) fputc(vm_read_byte(vm->emu->mem, 0x8000 + i), stderr);
  }
  else {
    for(i = 0; i < 0x80; i++) {
      fprintf(stderr, "%02x", vm_read_byte(vm->emu->mem, 0x8000 + i));
      fprintf(stderr, (i & 15) == 15 ? "\n" : " ");
    }
  }

  return ok;
}


void prepare_bios(vm_t *vm)
{
  unsigned u;
  x86emu_mem_t *mem = vm->emu->mem;

  vm->memsize = 1024;	// 1GB RAM

  // map_memory(vm, 0, 0x1000);

  if(opt.bios) {
    unsigned char buf[0x10000];
    int fd, i, j;

    fd = open(opt.bios, O_RDONLY);
    if(fd == -1) {
      perror(opt.bios);
    }
    else {
      memset(buf, 0, sizeof buf);
      i = read(fd, buf, sizeof buf);
      close(fd);
      if(i < 0) {
        perror(opt.bios);
      }
      else {
        lprintf("video bios: read %d bytes from %s\n", i, opt.bios);
        for(j = 0; j < i; j++) {
          vm_write_byte(mem, 0xc0000 + j, buf[j]);
        }
        lprintf("video bios: bios entry: 0xc000:0x%04x\n", opt.bios_entry);
        vm_write_word(mem, 0x10*4, opt.bios_entry);
        vm_write_word(mem, 0x10*4+2, 0xc000);
      }
    }
  }
  else {
    map_memory(mem, 0xc0000, 0x1000);
    if(vm_read_word(mem, 0xc0000) != 0xaa55) {
      lprintf("no video bios\n");
      return;
    }

    u = vm_read_byte(mem, 0xc0002) * 0x200;
    lprintf("video bios size: 0x%04x\n", u);
    map_memory(mem, 0xc0000, u);
  }

  // jmp far 0:0x7c00
  vm_write_byte(mem, 0xffff0, 0xea);
  vm_write_word(mem, 0xffff1, 0x7c00);
  vm_write_word(mem, 0xffff3, 0x0000);

  vm_write_word(mem, 0x7c00, 0x10cd);
  vm_write_byte(mem, 0x7c02, 0xf4);

  vm->emu->x86.R_EAX = 0x4f15;
  vm->emu->x86.R_EBX = 1;
  vm->emu->x86.R_ECX = opt.port;
  vm->emu->x86.R_EDX = 0;
  vm->emu->x86.R_EDI = 0x8000;
}


int map_memory(x86emu_mem_t *mem, off_t start, unsigned size)
{
  off_t map_start, xofs;
  int psize = getpagesize(), fd;
  unsigned map_size;
  void *p;
  struct stat sbuf;
  unsigned u;

  if(!size) return 0;

  map_start = start & -psize;
  xofs = start - map_start;

  map_size = (xofs + size + psize - 1) & -psize;

  fd = open("/dev/mem", O_RDONLY);

  if(fd == -1) return 0;

  if(!fstat(fd, &sbuf) && S_ISREG(sbuf.st_mode)) {
    if(sbuf.st_size < start + size) {
      if(sbuf.st_size > start) {
        size = sbuf.st_size - start;
      }
      else {
        size = 0;
      }
    }
  }

  if(!size) {
    close(fd);
    return 0;
  }

  p = mmap(NULL, map_size, PROT_READ, MAP_PRIVATE, fd, map_start);

  if(p == MAP_FAILED) {
    lprintf(
      "[0x%x, %u]: mmap(, %u,,,, 0x%x) failed: %s\n",
      (unsigned) start, size, map_size, (unsigned) map_start, strerror(errno)
    );
    close(fd);
    return 0;
  }
  lprintf(
    "[0x%x, %u]: mmap(, %u,,,, 0x%x) ok\n",
    (unsigned) start, size, map_size, (unsigned) map_start
  );

  for(u = 0; u < size; u++) {
    vm_write_byte(mem, start + u, *(unsigned char *) (p + xofs + u));
  }

  munmap(p, map_size);

  close(fd);

  return 1;
}


