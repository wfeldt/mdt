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

#define STR_SIZE 128

#define VBIOS_SIZE	0x10000

#define ADD_RES(w, h, f, i) \
  res[res_cnt].width = w, \
  res[res_cnt].height = h, \
  res[res_cnt].vfreq = f, \
  res[res_cnt++].il = i;

typedef struct {
  x86emu_t *emu;
} vm_t;


void lprintf(const char *format, ...) __attribute__ ((format (printf, 1, 2)));
void flush_log(x86emu_t *emu, char *buf, unsigned size);

void help(void);
void vm_write_byte(vm_t *vm, unsigned addr, unsigned val, unsigned perm);
void vm_write_word(vm_t *vm, unsigned addr, unsigned val, unsigned perm);
void vm_write_dword(vm_t *vm, unsigned addr, unsigned val, unsigned perm);
vm_t *vm_new(void);
void vm_free(vm_t *vm);
void vm_run(vm_t *vm);
int do_int(x86emu_t *emu, u8 num, unsigned type);
int prepare_bios(vm_t *vm);
void copy_to_vm(vm_t *vm, unsigned dst, unsigned char *src, unsigned size, unsigned perm);
void *map_mem(unsigned start, unsigned size);

void print_edid(int port, unsigned char *edid);
char *eisa_vendor(unsigned v);
char *canon_str(unsigned char *s, int len);
int chk_edid_info(unsigned char *edid);

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
  unsigned port;

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

  unsigned raw:1;
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
        opt.show.dumpinvmem = 1;
        opt.show.dumpattr = 1;
        opt.show.dumpregs = 1;
        opt.show.dumpints = 1;
        opt.show.dumpio = 1;
        opt.show.dumptime = 1;
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

  if(!prepare_bios(vm)) return 1;

  vm_run(vm);

  vm_free(vm);

  return 0;
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


void help()
{
  printf(
    "Get Monitor Data\nusage: gmd options\n"
    "  --port PORT_NUMBER\n"
    "      display port number to use. Default: 0, typically 0 - 3.\n"
    "  --show LIST\n"
    "      things to log\n"
    "      LIST is a comma-separated list of code, regs, data, io, ints, acc, tsc,\n"
    "      dump, dump.mem, dump.invmem, dump.attr, dump.regs, dump.io, dump.ints, dump.time\n"
    "  --no-show LIST\n"
    "      things not to log (see --show)\n"
    "  --raw\n"
    "      print DDC data in binary form to STDERR\n"
    "  --bios BIOS_IMAGE\n"
    "      use alternative Video BIOS (Don't try this at home!)\n"
    "  --bios-entry START_ADDRESS\n"
    "      specify start address for Video BIOS\n"
    "  --help\n"
    "      show this text\n"
  );
}


void vm_write_byte(vm_t *vm, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(vm->emu, addr, val);
  x86emu_set_perm(vm->emu, addr, addr, perm | X86EMU_ACC_W);
}


void vm_write_word(vm_t *vm, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(vm->emu, addr, val);
  x86emu_write_byte_noperm(vm->emu, addr + 1, val >> 8);
  x86emu_set_perm(vm->emu, addr, addr + 1, perm | X86EMU_ACC_W);
}


void vm_write_dword(vm_t *vm, unsigned addr, unsigned val, unsigned perm)
{
  x86emu_write_byte_noperm(vm->emu, addr, val);
  x86emu_write_byte_noperm(vm->emu, addr + 1, val >> 8);
  x86emu_write_byte_noperm(vm->emu, addr + 2, val >> 16);
  x86emu_write_byte_noperm(vm->emu, addr + 3, val >> 24);
  x86emu_set_perm(vm->emu, addr, addr + 3, perm | X86EMU_ACC_W);
}


int do_int(x86emu_t *emu, u8 num, unsigned type)
{
  if((type & 0xff) == INTR_TYPE_FAULT) x86emu_stop(emu);

  return 0;
}


vm_t *vm_new()
{
  vm_t *vm;

  vm = calloc(1, sizeof *vm);

  vm->emu = x86emu_new(0, X86EMU_PERM_RW);
  vm->emu->private = vm;

  x86emu_set_log(vm->emu, 200000000, flush_log);
  x86emu_set_intr_func(vm->emu, do_int);

  return vm;
}


void vm_free(vm_t *vm)
{
  x86emu_done(vm->emu);

  free(vm);
}


void vm_run(vm_t *vm)
{
  int i;
  unsigned char edid[0x80];

  if(opt.show.regs) vm->emu->log.regs = 1;
  if(opt.show.code) vm->emu->log.code = 1;
  if(opt.show.data) vm->emu->log.data = 1;
  if(opt.show.acc) vm->emu->log.acc = 1;
  if(opt.show.io) vm->emu->log.io = 1;
  if(opt.show.ints) vm->emu->log.ints = 1;
  if(opt.show.tsc) vm->emu->log.tsc = 1;

  if(x86emu_read_word(vm->emu, 0x7c00) == 0) return;

  // stack & buffer space
  x86emu_set_perm(vm->emu, 0x8000, 0xffff, X86EMU_PERM_RW);

  iopl(3);
  x86emu_run(vm->emu, X86EMU_RUN_LOOP | X86EMU_RUN_NO_CODE);
  iopl(0);

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
    x86emu_log(vm->emu, "\n; - - - emulator state\n");
    x86emu_dump(vm->emu, i);
    x86emu_log(vm->emu, "; - - -\n");
  }

  x86emu_clear_log(vm->emu, 1);

  printf("port = %u, eax = %08x\n", opt.port, vm->emu->x86.R_EAX);

  for(i = 0; i < 0x80; i++) edid[i] = x86emu_read_byte(vm->emu, 0x8000 + i);

  if(opt.raw) {
    for(i = 0; i < 0x80; i++) fputc(edid[i], stderr);
  }
  else {
    printf("- ddc data, port %d -\n", opt.port);
    for(i = 0; i < 0x80; i++) {
      printf("%02x", edid[i]);
      printf((i & 15) == 15 ? "\n" : " ");
    }
    printf("- -\n");
  }

  if(vm->emu->x86.R_EAX == 0x4f) {
    print_edid(opt.port, edid);
  }
  else {
    printf("Port %u: no monitor info\n", opt.port);
  }
}


int prepare_bios(vm_t *vm)
{
  int ok = 0;
  unsigned char *p1, *p2;

  if(opt.bios) {
    unsigned char buf[VBIOS_SIZE];
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
        lprintf("video bios: read %d bytes from %s\n", i, opt.bios);
        if(buf[0] != 0x55 || buf[1] != 0xaa || buf[2] == 0) {
          lprintf("error: no video bios\n");
          return ok;
        }

        lprintf("video bios: size: 0x%04x\n", buf[2] * 0x200);
        copy_to_vm(vm, 0xc0000, buf, buf[2] * 0x200, X86EMU_PERM_RX);

        lprintf("video bios: bios entry: 0xc000:0x%04x\n", opt.bios_entry);
        vm_write_word(vm, 0x10*4, opt.bios_entry, X86EMU_PERM_RW);
        vm_write_word(vm, 0x10*4+2, 0xc000, X86EMU_PERM_RW);
      }
    }
  }
  else {
    p1 = map_mem(0, 0x1000);
    if(!p1) {
      perror("/dev/mem");
      return ok;
    }

    copy_to_vm(vm, 0x10*4, p1 + 0x10*4, 4, X86EMU_PERM_RW);
    copy_to_vm(vm, 0x400, p1 + 0x400, 0x100, X86EMU_PERM_RW);

    munmap(p1, 0x1000);

    p2 = map_mem(0xc0000, VBIOS_SIZE);
    if(!p2 || p2[0] != 0x55 || p2[1] != 0xaa || p2[2] == 0) {
      if(p2) munmap(p2, VBIOS_SIZE);
      lprintf("error: no video bios\n");
      return ok;
    }

    lprintf("video bios size: 0x%04x\n", p2[2] * 0x200);
    copy_to_vm(vm, 0xc0000, p2, p2[2] * 0x200, X86EMU_PERM_RX);

    munmap(p2, VBIOS_SIZE);
  }

  // jmp far 0:0x7c00
  vm_write_byte(vm, 0xffff0, 0xea, X86EMU_PERM_RX);
  vm_write_word(vm, 0xffff1, 0x7c00, X86EMU_PERM_RX);
  vm_write_word(vm, 0xffff3, 0x0000, X86EMU_PERM_RX);

  vm_write_word(vm, 0x7c00, 0x10cd, X86EMU_PERM_RX);
  vm_write_byte(vm, 0x7c02, 0xf4, X86EMU_PERM_RX);

  vm->emu->x86.R_EAX = 0x4f15;
  vm->emu->x86.R_EBX = 1;
  vm->emu->x86.R_ECX = opt.port;
  vm->emu->x86.R_EDX = 0;
  vm->emu->x86.R_EDI = 0x8000;

  ok = 1;

  return ok;
}


void copy_to_vm(vm_t *vm, unsigned dst, unsigned char *src, unsigned size, unsigned perm)
{
  if(!size) return;

  while(size--) vm_write_byte(vm, dst++, *src++, perm);
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

  lprintf("[0x%x, %u]: mmap ok\n", start, size);

  close(fd);

  return p;
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
    printf("Port %u: no monitor info\n", port);
    return;
  }

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

  printf("Model: %s %04x", eisa_vendor(m.vendor_id), m.product_id);
  if(*m.vendor_name || *m.product_name) {
    printf(" (%s%s%s)", m.vendor_name, *m.vendor_name ? " " : "", m.product_name);
  }
  if(m.lcd) printf(" [LCD]");

  printf("\nManuf. Year: %u\n", m.year);

  if(mi_cnt) {
    u1 = mi_list[0].width_mm;
    u2 = mi_list[0].height_mm;
  }
  else {
    u1 = m.width_mm;
    u2 = m.height_mm;
  }

  printf("Size: %ux%u mm\n", u1, u2);

  printf("VSync: %u-%u Hz, HSync: %u-%u kHz\n", m.min_vsync, m.max_vsync, m.min_hsync, m.max_hsync);

  printf("Resolutions:\n");
  for(i = 0; i < res_cnt; i++) {
    printf("%s", i % 4 == 0 ? "  " : ", ");
    printf("%ux%u@%uHz%s",
      res[i].width, res[i].height, res[i].vfreq,
      res[i].il ? " (interlaced)" : ""
    );
    printf("%s", i % 4 == 3 ? "\n" : "");
  }
  printf("%s", i % 4 ? "\n" : "");

  for(i = 0; i < mi_cnt; i++)  {
    mi = mi_list + i;
    if(mi->htotal && mi->vtotal) {
      printf("Detailed Timings #%d:\n", i);
      printf("   Resolution: %ux%u\n", mi->width, mi->height);
      printf(
        "   Horizontal: %4u %4u %4u %4u (+%u +%u +%u) %chsync\n",
        mi->hdisp, mi->hsyncstart, mi->hsyncend, mi->htotal,
        mi->hsyncstart - mi->hdisp, mi->hsyncend - mi->hdisp, mi->htotal - mi->hdisp,
        mi->hflag
      );
      printf(
        "     Vertical: %4u %4u %4u %4u (+%u +%u +%u) %cvsync\n",
        mi->vdisp, mi->vsyncstart, mi->vsyncend, mi->vtotal,
        mi->vsyncstart - mi->vdisp, mi->vsyncend - mi->vdisp, mi->vtotal - mi->vdisp,
        mi->vflag
      );

      printf(
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


