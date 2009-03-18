#define _GNU_SOURCE

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
#include <sys/time.h>
#include <x86emu.h>

#define STR_SIZE 128

#define VBIOS_ROM	0xc0000
#define VBIOS_ROM_SIZE	0x10000

#define VBIOS_MEM	0xa0000
#define VBIOS_MEM_SIZE	0x10000

#define VBE_BUF		0x8000

#define ADD_RES(w, h, f, i) \
  res[res_cnt].width = w, \
  res[res_cnt].height = h, \
  res[res_cnt].vfreq = f, \
  res[res_cnt++].il = i;

typedef struct {
  x86emu_t *emu;
  unsigned char *video_mem;
} vm_t;


void help(void);
void lprintf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void flush_log(x86emu_t *emu, char *buf, unsigned size);

void vm_write_byte(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm);
void vm_write_word(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm);
void vm_write_dword(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm);
void copy_to_vm(x86emu_t *emu, unsigned dst, unsigned char *src, unsigned size, unsigned perm);
void copy_from_vm(x86emu_t *emu, void *dst, unsigned src, unsigned len);

int do_int(x86emu_t *emu, u8 num, unsigned type);
vm_t *vm_new(void);
void vm_free(vm_t *vm);
unsigned vm_run(x86emu_t *emu, double *t);
int vm_prepare(vm_t *vm);

double get_time(void);
void *map_mem(unsigned start, unsigned size);

void print_vbe_info(vm_t *vm, x86emu_t *emu, unsigned mode);
void list_modes(vm_t *vm, unsigned mode);

void probe_all(vm_t *vm);
int probe_port(vm_t *vm, unsigned port);

void print_edid(int port, unsigned char *edid);
char *eisa_vendor(unsigned v);
char *canon_str(unsigned char *s, int len);
int chk_edid_info(unsigned char *edid);


struct option options[] = {
  { "help",       0, NULL, 'h'  },
  { "verbose",    0, NULL, 'v'  },
  { "modes",      0, NULL, 1003 },
  { "mode",       1, NULL, 1004 },
  { "show",       1, NULL, 1005 },
  { "no-show",    1, NULL, 1006 },
  { "port",       1, NULL, 1007 },
  { "timeout",    1, NULL, 1008 },
  { "bios",       1, NULL, 1009 },
  { "bios-entry", 1, NULL, 1010 },
  { }
};

struct {
  unsigned port;
  unsigned port_set:1;
  unsigned verbose;
  unsigned timeout;

  unsigned all_modes:1;
  unsigned mode;
  unsigned mode_set:1;

  struct {
    unsigned code:1;
    unsigned regs:1;
    unsigned data:1;
    unsigned io:1;
    unsigned ints:1;
    unsigned acc:1;
    unsigned rawptable:1;
    unsigned dump:1;
    unsigned dumpmem:1;
    unsigned dumpinvmem:1;
    unsigned dumpattr:1;
    unsigned dumpregs:1;
    unsigned dumpints:1;
    unsigned dumpio:1;
    unsigned dumptime:1;
    unsigned tsc:1;
  } show;

  char *bios;
  unsigned bios_entry;

  FILE *log_file;
} opt;


int main(int argc, char **argv)
{
  int i, err;
  char *s, *t;
  unsigned u;
  vm_t *vm;

  opt.log_file = stdout;

  opterr = 0;

  while((i = getopt_long(argc, argv, "hv", options, NULL)) != -1) {
    err = 0;

    switch(i) {
      case 'v':
        opt.verbose++;
        break;

      case 1003:
        opt.all_modes = 1;
        break;

      case 1004:
        opt.mode = strtoul(optarg, NULL, 0);
        opt.mode_set = 1;
        break;

      case 1005:
      case 1006:
        if(opt.verbose < 2) opt.verbose = 2;
        s = optarg;
        u = i == 1005 ? 1 : 0;
        while((t = strsep(&s, ","))) {
          if(!strcmp(t, "code")) opt.show.code = u;
          else if(!strcmp(t, "regs")) opt.show.regs = u;
          else if(!strcmp(t, "data")) opt.show.data = u;
          else if(!strcmp(t, "io")) opt.show.io = u;
          else if(!strcmp(t, "ints")) opt.show.ints = u;
          else if(!strcmp(t, "acc")) opt.show.acc = u;
          else if(!strcmp(t, "dump")) opt.show.dump = u;
          else if(!strcmp(t, "dump.mem")) opt.show.dumpmem = u;
          else if(!strcmp(t, "dump.invmem")) opt.show.dumpinvmem = u;
          else if(!strcmp(t, "dump.attr")) opt.show.dumpattr = u;
          else if(!strcmp(t, "dump.regs")) opt.show.dumpregs = u;
          else if(!strcmp(t, "dump.ints")) opt.show.dumpints = u;
          else if(!strcmp(t, "dump.io")) opt.show.dumpio = u;
          else if(!strcmp(t, "dump.time")) opt.show.dumptime = u;
          else if(!strcmp(t, "tsc")) opt.show.tsc = u;
          else if(!strcmp(t, "trace")) {
            opt.show.regs = opt.show.data = opt.show.code =
            opt.show.io = opt.show.ints = u;
          }
          else err = 5;
        }
        break;

      case 1007:
        opt.port = strtoul(optarg, NULL, 0);
        opt.port_set = 1;
        break;

      case 1008:
        opt.timeout = strtoul(optarg, NULL, 0);
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

  if(!vm_prepare(vm)) return 1;

  if(opt.all_modes || opt.mode_set) {
    list_modes(vm, opt.mode_set ? opt.mode : 0);
  }
  else if(opt.port_set) {
    probe_port(vm, opt.port);
  }
  else {
    probe_all(vm);
  }

  vm_free(vm);

  return 0;
}


void help()
{
  printf(
    "Get Monitor Data\n"
    "Usage: gmd [OPTIONS]\n"
    "Read monitor data via Video BIOS and show the result.\n"
    "If used without any options it probes the first 4 display ports.\n"
    "This program needs root privileges to work properly.\n"
    "\n"
    "Options:\n"
    "  --port PORT_NUMBER\n"
    "      Display port number to use, typically 0 .. 3.\n"
    "  --timeout SECONDS\n"
    "      Maximum probing time (default: 20s).\n"
    "  --show LIST\n"
    "      Things to log. LIST is a comma-separated list of code, regs, data,\n"
    "      io, ints, acc, tsc, dump.mem, dump.invmem, dump.attr, dump.regs,\n"
    "      dump.io, dump.ints, dump.time.\n"
    "      Or use trace and dump as shorthands for a useful combination of items\n"
    "      from the above list.\n"
    "  --no-show LIST\n"
    "      Things not to log (see --show).\n"
    "  -v, --verbose\n"
    "      Show more log messages. Repeat option to show even more.\n"
    "  --bios BIOS_IMAGE_FILE\n"
    "      Use alternative Video BIOS (Don't try this at home!).\n"
    "  --bios-entry START_ADDRESS\n"
    "      In combination with --bios: start address for Video BIOS.\n"
    "  --modes\n"
    "      Show video mode list.\n"
    "  --mode MODE_NUMBER\n"
    "      Show info for video mode MODE_NUMBER.\n"
    "  -h, --help\n"
    "      Show this text.\n"
  );
}


void lprintf(const char *format, ...)
{
  va_list args;

  va_start(args, format);
  if(opt.log_file) vfprintf(opt.log_file, format, args);
  va_end(args);
}


void flush_log(x86emu_t *emu, char *buf, unsigned size)
{
  if(!buf || !size || !opt.log_file) return;

  fwrite(buf, size, 1, opt.log_file);
}


unsigned vm_read_segofs16(x86emu_t *emu, unsigned addr)
{
  return x86emu_read_word(emu, addr) + (x86emu_read_word(emu, addr + 2) << 4);
}


void vm_write_byte(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(emu, addr, val);
  x86emu_set_perm(emu, addr, addr, perm | X86EMU_PERM_VALID);
}


void vm_write_word(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(emu, addr, val);
  x86emu_write_byte_noperm(emu, addr + 1, val >> 8);
  x86emu_set_perm(emu, addr, addr + 1, perm | X86EMU_PERM_VALID);
}


void vm_write_dword(x86emu_t *emu, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(emu, addr, val);
  x86emu_write_byte_noperm(emu, addr + 1, val >> 8);
  x86emu_write_byte_noperm(emu, addr + 2, val >> 16);
  x86emu_write_byte_noperm(emu, addr + 3, val >> 24);
  x86emu_set_perm(emu, addr, addr + 3, perm | X86EMU_PERM_VALID);
}


void copy_to_vm(x86emu_t *emu, unsigned dst, unsigned char *src, unsigned size, unsigned perm)
{
  if(!size) return;

  while(size--) vm_write_byte(emu, dst++, *src++, perm);
}


void copy_from_vm(x86emu_t *emu, void *dst, unsigned src, unsigned len)
{
  unsigned char *p = dst;
  unsigned u;

  for(u = 0; u < len; u++) {
    p[u] = x86emu_read_byte_noperm(emu, src + u);
  }
}


int do_int(x86emu_t *emu, u8 num, unsigned type)
{
  if((type & 0xff) == INTR_TYPE_FAULT) {
    x86emu_stop(emu);

    return 0;
  }

  // ignore ints != 0x10
  if(num != 0x10) return 1;

  return 0;
}


vm_t *vm_new()
{
  vm_t *vm;

  vm = calloc(1, sizeof *vm);

  vm->emu = x86emu_new(0, X86EMU_PERM_RW);
  vm->emu->private = vm;

  x86emu_set_log(vm->emu, 200000000, flush_log);
  x86emu_set_intr_handler(vm->emu, do_int);

  return vm;
}


void vm_free(vm_t *vm)
{
  x86emu_done(vm->emu);

  free(vm);
}


unsigned vm_run(x86emu_t *emu, double *t)
{
  int i;
  unsigned err;

  if(opt.verbose >= 2) x86emu_log(emu, "=== emulation log ===\n");

  *t = get_time();

  iopl(3);
  err = x86emu_run(emu, X86EMU_RUN_LOOP | X86EMU_RUN_NO_CODE | X86EMU_RUN_TIMEOUT);
  iopl(0);

  *t = get_time() - *t;

  i = 0;
  if(opt.show.dump) i |= -1;
  if(opt.show.dumpinvmem) {
    i |= X86EMU_DUMP_INV_MEM;
    i &= ~X86EMU_DUMP_MEM;
  }
  if(opt.show.dumpmem) {
    i |= X86EMU_DUMP_MEM;
    i &= ~X86EMU_DUMP_INV_MEM;
  }
  if(opt.show.dumpattr) i |= X86EMU_DUMP_ATTR;
  if(opt.show.dumpregs) i |= X86EMU_DUMP_REGS;
  if(opt.show.dumpints) i |= X86EMU_DUMP_INTS;
  if(opt.show.dumpio) i |= X86EMU_DUMP_IO;
  if(opt.show.dumptime) i |= X86EMU_DUMP_TIME;

  if(i) {
    x86emu_log(emu, "\n; - - - final state\n");
    x86emu_dump(emu, i);
    x86emu_log(emu, "; - - -\n");
  }

  if(opt.verbose >= 2) x86emu_log(emu, "=== emulation log end ===\n");

  x86emu_clear_log(emu, 1);

  return err;
}


int vm_prepare(vm_t *vm)
{
  int ok = 0;
  unsigned u;
  unsigned char *p1, *p2;

  if(opt.verbose >= 2) lprintf("=== bios setup ===\n");

  if(opt.bios) {
    unsigned char buf[VBIOS_ROM_SIZE];
    int fd, i;

    fd = open(opt.bios, O_RDONLY);
    if(fd == -1) {
      perror(opt.bios);
      return ok;
    }
    else {
      memset(buf, 0, sizeof buf);
      i = read(fd, buf, sizeof buf);
      close(fd);
      if(i < 0) {
        perror(opt.bios);
        return ok;
      }
      else {
        if(opt.verbose >= 2) lprintf("video bios: read %d bytes from %s\n", i, opt.bios);
        if(buf[0] != 0x55 || buf[1] != 0xaa || buf[2] == 0) {
          lprintf("error: no video bios\n");
          return ok;
        }

        copy_to_vm(vm->emu, VBIOS_ROM, buf, buf[2] * 0x200, X86EMU_PERM_RX);

        vm_write_word(vm->emu, 0x10*4, opt.bios_entry, X86EMU_PERM_RW);
        vm_write_word(vm->emu, 0x10*4+2, VBIOS_ROM >> 4, X86EMU_PERM_RW);
      }
    }
  }
  else {
    p1 = map_mem(0, 0x1000);
    if(!p1) {
      perror("/dev/mem");
      return ok;
    }

    copy_to_vm(vm->emu, 0x10*4, p1 + 0x10*4, 4, X86EMU_PERM_RW);
    copy_to_vm(vm->emu, 0x400, p1 + 0x400, 0x100, X86EMU_PERM_RW);

    munmap(p1, 0x1000);

    p2 = map_mem(VBIOS_ROM, VBIOS_ROM_SIZE);
    if(!p2 || p2[0] != 0x55 || p2[1] != 0xaa || p2[2] == 0) {
      if(p2) munmap(p2, VBIOS_ROM_SIZE);
      lprintf("error: no video bios\n");
      return ok;
    }

    copy_to_vm(vm->emu, VBIOS_ROM, p2, p2[2] * 0x200, X86EMU_PERM_RX);

    munmap(p2, VBIOS_ROM_SIZE);
  }

  if(opt.verbose >= 2) {
    lprintf("video bios: size 0x%04x\n", x86emu_read_byte(vm->emu, VBIOS_ROM + 2) * 0x200);
    lprintf("video bios: entry 0x%04x:0x%04x\n",
      x86emu_read_word(vm->emu, 0x10*4 +  2),
      x86emu_read_word(vm->emu, 0x10*4)
    );
  }

  // video memory
  vm->video_mem = map_mem(VBIOS_MEM, VBIOS_MEM_SIZE);

  if(vm->video_mem) {
    x86emu_set_perm(vm->emu, VBIOS_MEM, VBIOS_MEM + VBIOS_MEM_SIZE - 1, X86EMU_PERM_RW);
    for(u = 0; u < VBIOS_MEM_SIZE; u += X86EMU_PAGE_SIZE) {
      x86emu_set_page(vm->emu, VBIOS_MEM + u, vm->video_mem + u);
    }
  }

  // jmp far 0:0x7c00
  vm_write_byte(vm->emu, 0xffff0, 0xea, X86EMU_PERM_RX);
  vm_write_word(vm->emu, 0xffff1, 0x7c00, X86EMU_PERM_RX);
  vm_write_word(vm->emu, 0xffff3, 0x0000, X86EMU_PERM_RX);

  // int 0x10 ; hlt
  vm_write_word(vm->emu, 0x7c00, 0x10cd, X86EMU_PERM_RX);
  vm_write_byte(vm->emu, 0x7c02, 0xf4, X86EMU_PERM_RX);

  // stack & buffer space
  x86emu_set_perm(vm->emu, VBE_BUF, 0xffff, X86EMU_PERM_RW);

  if(opt.show.regs) vm->emu->log.regs = 1;
  if(opt.show.code) vm->emu->log.code = 1;
  if(opt.show.data) vm->emu->log.data = 1;
  if(opt.show.acc) vm->emu->log.acc = 1;
  if(opt.show.io) vm->emu->log.io = 1;
  if(opt.show.ints) vm->emu->log.ints = 1;
  if(opt.show.tsc) vm->emu->log.tsc = 1;

  if(opt.timeout) vm->emu->timeout = opt.timeout ?: 20;

  ok = 1;

  return ok;
}


double get_time()
{
  static struct timeval t0 = { };
  struct timeval t1 = { };

  gettimeofday(&t1, NULL);

  if(!timerisset(&t0)) t0 = t1;

  timersub(&t1, &t0, &t1);

  return t1.tv_sec + t1.tv_usec / 1e6;
}


void *map_mem(unsigned start, unsigned size)
{
  int fd;
  void *p;

  if(!size) return NULL;

  fd = open("/dev/mem", O_RDONLY);

  if(fd == -1) return NULL;

  p = mmap(NULL, size, PROT_READ, MAP_PRIVATE, fd, start);

  if(p == MAP_FAILED) {
    lprintf("error: [0x%x, %u]: mmap failed: %s\n", start, size, strerror(errno));
    close(fd);

    return NULL;
  }

  if(opt.verbose >= 3) lprintf("[0x%x, %u]: mmap ok\n", start, size);

  close(fd);

  return p;
}


void print_vbe_info(vm_t *vm, x86emu_t *emu, unsigned mode)
{
  unsigned char buf2[0x100];
  unsigned u, ml;
  unsigned modelist[0x100];
  unsigned modes, number;
  int err;
  double d;
  char s[64];
  unsigned version, oem_version, memory, attributes, width, height, bytes_p_line;
  unsigned win_A_start, win_B_start, win_A_attr, win_B_attr, win_gran, win_size;
  unsigned bpp, res_bpp, fb_start, pixel_clock;

  version = x86emu_read_word(emu, VBE_BUF + 0x04);
  oem_version = x86emu_read_word(emu, VBE_BUF + 0x14);
  memory = x86emu_read_word(emu, VBE_BUF + 0x12) << 16;

  if(!mode) {
    lprintf(
      "version = %u.%u, oem version = %u.%u\n",
      version >> 8, version & 0xff, oem_version >> 8, oem_version & 0xff
    );

    lprintf("memory = %uk\n", memory >> 10);

    buf2[sizeof buf2 - 1] = 0;

    u = vm_read_segofs16(emu, VBE_BUF + 0x06);
    copy_from_vm(emu, buf2, u, sizeof buf2 - 1);
    lprintf("oem name [0x%05x] = \"%s\"\n", u, buf2);

    u = vm_read_segofs16(emu, VBE_BUF + 0x16);
    copy_from_vm(emu, buf2, u, sizeof buf2 - 1);
    lprintf("vendor name [0x%05x] = \"%s\"\n", u, buf2);

    u = vm_read_segofs16(emu, VBE_BUF + 0x1a);
    copy_from_vm(emu, buf2, u, sizeof buf2 - 1);
    lprintf("product name [0x%05x] = \"%s\"\n", u, buf2);

    u = vm_read_segofs16(emu, VBE_BUF + 0x1e);
    copy_from_vm(emu, buf2, u, sizeof buf2 - 1);
    lprintf("product revision [0x%05x] = \"%s\"\n", u, buf2);
  }

  ml = vm_read_segofs16(emu, VBE_BUF + 0x0e);

  for(modes = 0; modes < sizeof modelist / sizeof *modelist; ) {
    u = x86emu_read_word(emu, ml + 2 * modes);
    if(u == 0xffff) break;
    modelist[modes++] = u;
  }

  if(!mode) lprintf("%u video modes:\n", modes);

  emu = NULL;

  for(u = 0; u < modes; u++) {
    number = modelist[u];
    if(mode && number != mode) continue;

    x86emu_done(emu);
    emu = x86emu_clone(vm->emu);

    emu->x86.R_EAX = 0x4f01;
    emu->x86.R_EBX = 0;
    emu->x86.R_ECX = number;
    emu->x86.R_EDX = 0;
    emu->x86.R_EDI = VBE_BUF;

    err = vm_run(emu, &d);

    if(opt.verbose >= 1) lprintf("=== vbe get mode info (0x%04x): %s (time %.3fs, eax 0x%x, err = 0x%x)\n",
      number,
      emu->x86.R_AX == 0x4f ? "ok" : "failed",
      d,
      emu->x86.R_EAX,
      err
    );

    if(err || emu->x86.R_AX != 0x4f) {
      lprintf("  0x%04x: no mode info\n", number);
      continue;
    }

    attributes = x86emu_read_word(emu, VBE_BUF + 0x00);

    width = x86emu_read_word(emu, VBE_BUF + 0x12);
    height = x86emu_read_word(emu, VBE_BUF + 0x14);
    bytes_p_line = x86emu_read_word(emu, VBE_BUF + 0x10);

    win_A_start = x86emu_read_word(emu, VBE_BUF + 0x08) << 4;
    win_B_start = x86emu_read_word(emu, VBE_BUF + 0x0a) << 4;

    win_A_attr = x86emu_read_byte(emu, VBE_BUF + 0x02);
    win_B_attr = x86emu_read_byte(emu, VBE_BUF + 0x03);

    win_gran = x86emu_read_word(emu, VBE_BUF + 0x04) << 10;
    win_size = x86emu_read_word(emu, VBE_BUF + 0x06) << 10;

    bpp = res_bpp = 0;

    switch(x86emu_read_byte(emu, VBE_BUF + 0x1b)) {
      case 0:
        bpp = -1;
        break;

      case 1:
        bpp = 2;
        break;

      case 2:
        bpp = 1;
        break;

      case 3:
        bpp = 4;
        break;

      case 4:
        bpp = 8;
        break;

      case 6:
        bpp = x86emu_read_byte(emu, VBE_BUF + 0x1f) +
          x86emu_read_byte(emu, VBE_BUF + 0x21) +
          x86emu_read_byte(emu, VBE_BUF + 0x23);
        res_bpp = x86emu_read_byte(emu, VBE_BUF + 0x19) - bpp;
        if(res_bpp < 0) res_bpp = 0;
    }

    fb_start = version >= 0x0200 ? x86emu_read_dword(emu, VBE_BUF + 0x28) : 0;

    pixel_clock = version >= 0x0300 ? x86emu_read_dword(emu, VBE_BUF + 0x3e) : 0;

    if(bpp == -1u) {
      lprintf("  0x%04x[%02x]: %ux%u, text\n", number, attributes, width, height);
    }
    else {
      *s = 0;
      if(res_bpp) sprintf(s, "+%d", res_bpp);
      lprintf("  0x%04x[%02x]: %ux%u+%u, %u%s bpp",
        number, attributes, width, height, bytes_p_line, bpp, s
      );

      if(pixel_clock) lprintf(", max. %u MHz", pixel_clock/1000000);
      if(fb_start) lprintf(", fb: 0x%08x", fb_start);
      lprintf(", %04x.%x", win_A_start, win_A_attr);
      if(win_B_start || win_B_attr) lprintf("/%04x.%x", win_B_start, win_B_attr);
      lprintf(": %uk", win_size >> 10);
      if(win_gran != win_size) lprintf("/%uk", win_gran >> 10);
      lprintf("\n");
    }
  }

  emu = x86emu_done(emu);
}


void list_modes(vm_t *vm, unsigned mode)
{
  x86emu_t *emu = NULL;
  int err = 0;
  double d, timeout;

  if(opt.verbose >= 1) lprintf("=== running bios\n");

  timeout = get_time() + (opt.timeout ?: 20);

  emu = x86emu_clone(vm->emu);

  emu->x86.R_EAX = 0x4f00;
  emu->x86.R_EBX = 0;
  emu->x86.R_ECX = 0;
  emu->x86.R_EDX = 0;
  emu->x86.R_EDI = VBE_BUF;

  x86emu_write_dword(emu, VBE_BUF, 0x32454256);		// "VBE2"

  err = vm_run(emu, &d);

  if(opt.verbose >= 1) lprintf("=== vbe get info: %s (time %.3fs, eax 0x%x, err = 0x%x)\n",
    emu->x86.R_AX == 0x4f ? "ok" : "failed",
    d,
    emu->x86.R_EAX,
    err
  );

  if(!err && emu->x86.R_AX == 0x4f) {
    if(opt.verbose >= 1) lprintf("=== vbe info\n");
    print_vbe_info(vm, emu, mode);
  }
  else {
    lprintf("=== no vbe info\n");
  }

  x86emu_done(emu);
}


void probe_all(vm_t *vm)
{
  x86emu_t *emu = NULL;
  int err = 0, i;
  unsigned port, cnt;
  double d, timeout;
  unsigned char edid[0x80];

  if(opt.verbose >= 1) lprintf("=== running bios\n");

  timeout = get_time() + (opt.timeout ?: 20);

  for(port = 0; port < 4; port++) {
    for(cnt = 0; cnt < 2 && get_time() <= timeout; cnt++) {
      emu = x86emu_done(emu);
      emu = x86emu_clone(vm->emu);

      emu->x86.R_EAX = 0x4f15;
      emu->x86.R_EBX = 1;
      emu->x86.R_ECX = port;
      emu->x86.R_EDX = 0;
      emu->x86.R_EDI = VBE_BUF;

      err = vm_run(emu, &d);

      if(opt.verbose >= 2) lprintf("=== port %u, try %u: %s (time %.3fs, eax 0x%x, err = 0x%x)\n",
        port,
        cnt,
        emu->x86.R_AX == 0x4f ? "ok" : "failed",
        d,
        emu->x86.R_EAX,
        err
      );

      if(err || emu->x86.R_AX == 0x4f) break;
    }

    if(!emu) {
      lprintf("=== timeout\n");
      break;
    }

    if(opt.verbose == 1) lprintf("=== port %u: %s (time %.3fs, eax 0x%x, err = 0x%x)\n",
      port,
      emu->x86.R_AX == 0x4f ? "ok" : "failed",
      d,
      emu->x86.R_EAX,
      err
    );

    for(i = 0; i < 0x80; i++) edid[i] = x86emu_read_byte(emu, VBE_BUF + i);

    if(opt.verbose >= 2) {
      lprintf("=== port %u: ddc data ===\n", port);
      for(i = 0; i < 0x80; i++) {
        lprintf("%02x", edid[i]);
        lprintf((i & 15) == 15 ? "\n" : " ");
      }
      lprintf("=== port %u: ddc data end ===\n", port);
    }

    if(!err && emu->x86.R_AX == 0x4f) {
      lprintf("=== port %u: monitor info\n", port);
      print_edid(port, edid);
    }
    else {
      if(!err) err = -1;
      lprintf("=== port %u: no monitor info\n", port);
    }

    emu = x86emu_done(emu);
  }
}


int probe_port(vm_t *vm, unsigned port)
{
  x86emu_t *emu;
  int err = 0, i;
  double d;
  unsigned char edid[0x80];

  if(opt.verbose >= 1) lprintf("=== port %u: running bios\n", port);

  emu = x86emu_clone(vm->emu);

  emu->x86.R_EAX = 0x4f15;
  emu->x86.R_EBX = 1;
  emu->x86.R_ECX = port;
  emu->x86.R_EDX = 0;
  emu->x86.R_EDI = VBE_BUF;

  err = vm_run(emu, &d);

  if(opt.verbose >= 1) lprintf("=== port %u: %s (time %.3fs, eax 0x%x, err = 0x%x)\n",
    port,
    emu->x86.R_AX == 0x4f ? "ok" : "failed",
    d,
    emu->x86.R_EAX,
    err
  );

  for(i = 0; i < 0x80; i++) edid[i] = x86emu_read_byte(emu, VBE_BUF + i);

  if(opt.verbose >= 2) {
    lprintf("=== port %u: ddc data ===\n", port);
    for(i = 0; i < 0x80; i++) {
      lprintf("%02x", edid[i]);
      lprintf((i & 15) == 15 ? "\n" : " ");
    }
    lprintf("=== port %u: ddc data end ===\n", port);
  }

  if(!err && emu->x86.R_AX == 0x4f) {
    if(opt.verbose >= 1) lprintf("=== port %u: monitor info\n", port);
    print_edid(port, edid);
  }
  else {
    if(!err) err = -1;
    lprintf("=== port %u: no monitor info\n", port);
  }

  x86emu_done(emu);

  return err;
}


void print_edid(int port, unsigned char *edid)
{
  int i;
  unsigned u, u1, u2, tag, mi_cnt = 0, res_cnt = 0;
  unsigned hblank, hsync_ofs, hsync, vblank, vsync_ofs, vsync;
  char *s;
  struct {
    unsigned lcd:1;
    unsigned vendor_id, product_id;
    unsigned width_mm, height_mm;
    unsigned year;
    unsigned min_vsync, max_vsync, min_hsync, max_hsync;
    unsigned hblank, hsync_ofs, hsync, vblank, vsync_ofs, vsync;
    char vendor_name[STR_SIZE], product_name[STR_SIZE], serial[STR_SIZE];
  } m = { };
  struct {
    unsigned width, height, width_mm, height_mm, clock;
    unsigned hdisp, hsyncstart, hsyncend, htotal, hflag;
    unsigned vdisp, vsyncstart, vsyncend, vtotal, vflag;
  } mi_list[4] = { }, *mi;
  struct {
    unsigned width, height, vfreq, il;
  } res[24] = { };


  if(!chk_edid_info(edid)) {
    lprintf("Port %u: no monitor info\n", port);
    return;
  }

  // lprintf("Port: %u\n", port);

  if(edid[0x14] & 0x80) m.lcd = 1;

  m.vendor_id = (edid[8] << 8) + edid[9];
  m.product_id = (edid[0xb] << 8) + edid[0xa];

  if(edid[0x15] > 0 && edid[0x16] > 0) {
    m.width_mm = edid[0x15] * 10;
    m.height_mm = edid[0x16] * 10;
  }

  m.year = 1990 + edid[0x11];

  u = edid[0x23];
  if(u & (1 << 7)) ADD_RES(720, 400, 70, 0);
  if(u & (1 << 6)) ADD_RES(720, 400, 88, 0);
  if(u & (1 << 5)) ADD_RES(640, 480, 60, 0);
  if(u & (1 << 4)) ADD_RES(640, 480, 67, 0);
  if(u & (1 << 3)) ADD_RES(640, 480, 72, 0);
  if(u & (1 << 2)) ADD_RES(640, 480, 75, 0);
  if(u & (1 << 1)) ADD_RES(800, 600, 56, 0);
  if(u & (1 << 0)) ADD_RES(800, 600, 60, 0);

  u = edid[0x24];
  if(u & (1 << 7)) ADD_RES( 800,  600, 72, 0);
  if(u & (1 << 6)) ADD_RES( 800,  600, 75, 0);
  if(u & (1 << 5)) ADD_RES( 832,  624, 75, 0);
  if(u & (1 << 4)) ADD_RES(1024,  768, 87, 1);
  if(u & (1 << 3)) ADD_RES(1024,  768, 60, 0);
  if(u & (1 << 2)) ADD_RES(1024,  768, 70, 0);
  if(u & (1 << 1)) ADD_RES(1024,  768, 75, 0);
  if(u & (1 << 0)) ADD_RES(1280, 1024, 75, 0);

  for(i = 0; i < 4; i++) {
    u1 = (edid[0x26 + 2 * i] + 31) * 8;
    u2 = edid[0x27 + 2 * i];
    u = 0;
    switch((u2 >> 6) & 3) {
      case 1: u = (u1 * 3) / 4; break;
      case 2: u = (u1 * 4) / 5; break;
      case 3: u = (u1 * 9) / 16; break;
    }
    if(u) {
      ADD_RES(u1, u, (u2 & 0x3f) + 60, 0);
    }
  }

  // detailed timings

  /* max. 4 mi_list[] entries */
  for(i = 0x36; i < 0x36 + 4 * 0x12; i += 0x12) {
    tag = (edid[i] << 24) + (edid[i + 1] << 16) + (edid[i + 2] << 8) + edid[i + 3];

    switch(tag) {
      case 0xfc:
        if(edid[i + 5]) {
          /* name entry is splitted some times */
          // str_printf(&name, -1, "%s%s", name ? " " : "", canon_str(edid + i + 5, 0xd));
          memcpy(m.product_name, canon_str(edid + i + 5, 0xd), sizeof m.product_name);
        }
        break;

      case 0xfd:
        u = 0;
        u1 = edid[i + 5];
        u2 = edid[i + 6];
        if(u1 > u2 || !u1) u = 1;
        m.min_vsync = u1;
        m.max_vsync = u2;
        u1 = edid[i + 7];
        u2 = edid[i + 8];
        if(u1 > u2 || !u1) u = 1;
        m.min_hsync = u1;
        m.max_hsync = u2;
        if(u) {
          m.min_vsync = m.max_vsync = m.min_hsync = m.max_hsync = 0;
        }
        break;

      case 0xfe:
        if(!*m.vendor_name && edid[i + 5]) {
          memcpy(m.vendor_name, canon_str(edid + i + 5, 0xd), sizeof m.vendor_name);
          for(s = m.vendor_name; *s; s++) if(*s < ' ') *s = ' ';
        }
        break;

      case 0xff:
        if(!*m.serial && edid[i + 5]) {
          memcpy(m.serial, canon_str(edid + i + 5, 0xd), sizeof m.serial);
          for(s = m.serial; *s; s++) if(*s < ' ') *s = ' ';
        }
        break;

      default:
        if(tag < 0x100) {
        }
        else {
          mi = mi_list + mi_cnt++;

          mi->width_mm = m.width_mm;
          mi->height_mm = m.height_mm;

          u = (edid[i + 0] + (edid[i + 1] << 8)) * 10;	/* pixel clock in kHz */
          if(!u) break;
          mi->clock = u;

          u1 = edid[i + 2] + ((edid[i + 4] & 0xf0) << 4);
          u2 = edid[i + 5] + ((edid[i + 7] & 0xf0) << 4);
          if(!u1 || !u2 || u1 == 0xfff || u2 == 0xfff) break;
          mi->width = u1;
          mi->height = u2;

          u1 = edid[i + 12] + ((edid[i + 14] & 0xf0) << 4);
          u2 = edid[i + 13] + ((edid[i + 14] & 0xf) << 8);
          if(!u1 || !u2 || u1 == 0xfff || u2 == 0xfff) break;
          mi->width_mm = u1;
          mi->height_mm = u2;

          hblank = edid[i + 3] + ((edid[i + 4] & 0xf) << 8);
          hsync_ofs = edid[i + 8] + ((edid[i + 11] & 0xc0) << 2);
          hsync = edid[i + 9] + ((edid[i + 11] & 0x30) << 4);

          vblank = edid[i + 6] + ((edid[i + 7] & 0xf) << 8);
          vsync_ofs = ((edid[i + 10] & 0xf0) >> 4) + ((edid[i + 11] & 0x0c) << 2);
          vsync = (edid[i + 10] & 0xf) + ((edid[i + 11] & 0x03) << 4);

          mi->hdisp       = mi->width;
          mi->hsyncstart  = mi->width + hsync_ofs;
          mi->hsyncend    = mi->width + hsync_ofs + hsync;
          mi->htotal      = mi->width + hblank;

          mi->vdisp       = mi->height;
          mi->vsyncstart  = mi->height + vsync_ofs;
          mi->vsyncend    = mi->height + vsync_ofs + vsync;
          mi->vtotal      = mi->height + vblank;

          u = edid[i + 17];

          if(((u >> 3) & 3) == 3) {
            mi->hflag = (u & 4) ? '+' : '-';
            mi->vflag = (u & 2) ? '+' : '-';
          }
        }
    }
  }

  for(i = 0; i < mi_cnt; i++) {
    mi = mi_list + i;

    if(mi->width && mi->height) {
      ADD_RES(mi->width, mi->height, 60, 0);

      if(mi->width_mm && mi->height_mm) {
        u = (mi->width_mm * mi->height * 16) / (mi->height_mm * mi->width);
        u1 = m.width_mm ? (m.width_mm * 16) / mi->width_mm : 16;
        u2 = m.height_mm ? (m.height_mm * 16) / mi->height_mm : 16;
        if(
          u <= 8 || u >= 32 ||		/* allow 1:2 distortion */
          u1 <= 8 || u1 >= 32 ||	/* width cm & mm values disagree by factor >2 --> use cm values */
          u2 <= 8 || u2 >= 32 ||	/* dto, height */
          mi->width_mm < 100 ||		/* too small to be true... */
          mi->height_mm < 100
        ) {
          /* ok, try cm values */
          if(m.width_mm && m.height_mm) {
            u = (m.width_mm * mi->height * 16) / (m.height_mm * mi->width);
            if(u > 8 && u < 32 && m.width_mm >= 100 && m.height_mm >= 100) {
              mi->width_mm = m.width_mm;
              mi->height_mm = m.height_mm;
            }
          }
          /* could not fix, clear */
          if(u <= 8 || u >= 32 || mi->width_mm < 100 || mi->height_mm < 100) {
            mi->width_mm = mi->height_mm = 0;
          }
        }
      }
    }
  }

  lprintf("Model: %s %04x", eisa_vendor(m.vendor_id), m.product_id);
  if(*m.vendor_name || *m.product_name) {
    lprintf(" (%s%s%s)", m.vendor_name, *m.vendor_name ? " " : "", m.product_name);
  }
  if(m.lcd) lprintf(" [LCD]");

  lprintf("\nManuf. Year: %u\n", m.year);

  if(mi_cnt) {
    u1 = mi_list[0].width_mm;
    u2 = mi_list[0].height_mm;
  }
  else {
    u1 = m.width_mm;
    u2 = m.height_mm;
  }

  lprintf("Size: %ux%u mm\n", u1, u2);

  lprintf("VSync: %u-%u Hz, HSync: %u-%u kHz\n", m.min_vsync, m.max_vsync, m.min_hsync, m.max_hsync);

  lprintf("Resolutions:\n");
  for(i = 0; i < res_cnt; i++) {
    lprintf("%s", i % 4 == 0 ? "  " : ", ");
    lprintf("%ux%u@%uHz%s",
      res[i].width, res[i].height, res[i].vfreq,
      res[i].il ? " (interlaced)" : ""
    );
    lprintf("%s", i % 4 == 3 ? "\n" : "");
  }
  lprintf("%s", i % 4 ? "\n" : "");

  for(i = 0; i < mi_cnt; i++)  {
    mi = mi_list + i;
    if(mi->htotal && mi->vtotal) {
      lprintf("Detailed Timings #%d:\n", i);
      lprintf("   Resolution: %ux%u\n", mi->width, mi->height);
      lprintf(
        "   Horizontal: %4u %4u %4u %4u (+%u +%u +%u) %chsync\n",
        mi->hdisp, mi->hsyncstart, mi->hsyncend, mi->htotal,
        mi->hsyncstart - mi->hdisp, mi->hsyncend - mi->hdisp, mi->htotal - mi->hdisp,
        mi->hflag
      );
      lprintf(
        "     Vertical: %4u %4u %4u %4u (+%u +%u +%u) %cvsync\n",
        mi->vdisp, mi->vsyncstart, mi->vsyncend, mi->vtotal,
        mi->vsyncstart - mi->vdisp, mi->vsyncend - mi->vdisp, mi->vtotal - mi->vdisp,
        mi->vflag
      );

      lprintf(
        "  Frequencies: %u.%02u MHz, %u.%02u kHz, %u.%02u Hz\n",
        mi->clock / 1000, (mi->clock * 100 / 1000) % 100,
        mi->clock / mi->htotal, (mi->clock * 100 / mi->htotal) % 100,
        mi->clock * 1000 / mi->htotal / mi->vtotal, 0
      );
    }
  }
}


char *eisa_vendor(unsigned v)
{
  static char s[4];

  s[0] = ((v >> 10) & 0x1f) + 'A' - 1;
  s[1] = ((v >>  5) & 0x1f) + 'A' - 1;
  s[2] = ( v        & 0x1f) + 'A' - 1;
  s[3] = 0;

  return s;
}


char *canon_str(unsigned char *s, int len)
{
  static char m0[STR_SIZE];
  char *m1;
  int i;

  if(len < 0) len = 0;          /* just to be safe */
  if(len > sizeof m0 - 1) len = sizeof m0 - 1;

  for(m1 = m0, i = 0; i < len; i++) {
    if(m1 == m0 && s[i] <= ' ') continue;
    *m1++ = s[i];
  }
  *m1 = 0;
  while(m1 > m0 && m1[-1] <= ' ') {
    *--m1 = 0;
  }

  return m0;
}


/* do some checks to ensure we got a reasonable block */
int chk_edid_info(unsigned char *edid)
{
  // no vendor or model info
  if(!(edid[0x08] || edid[0x09] || edid[0x0a] || edid[0x0b])) return 0;

  // no edid version or revision
  if(!(edid[0x12] || edid[0x13])) return 0;

  return 1;
}


