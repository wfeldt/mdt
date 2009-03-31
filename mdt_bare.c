/*
 *
 * mdt.c	monitor detection tool
 *
 * Copyright (c) 2008 Steffen Winterfeldt.
 *
 * For details see file COPYING.
 *
 */

#include <libio.h>

#define STR_SIZE 128

#define ADD_RES(w, h, f, i) \
  res[res_cnt].width = w, \
  res[res_cnt].height = h, \
  res[res_cnt].vfreq = f, \
  res[res_cnt++].il = i;

void print_edid(int port);
char *eisa_vendor(unsigned v);
char *canon_str(char *s, int len);
int chk_edid_info(unsigned char *edid);
unsigned probe_ddc(int port, unsigned char *edid);


int main()
{
  int key;

  clrscr();

  printf("Video BIOS monitor detection tool v1.1.\n\n");

  do {
    printf("Select display port to check (0-7) or ESC to abort: ");
    key = getchar();
    if(key >= ' ') printf("%c\n", key);

    if(key >= '0' && key < '8') print_edid(key - '0');

  } while(key != 0x1b && key != 3 && key != 4 && key != 'q' && key != 0x11);

  return 0;
}


void print_edid(int port)
{
  int i;
  unsigned u, u1, u2, tag, mi_cnt = 0, res_cnt = 0;
  unsigned char edid[0x80];
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


  u = probe_ddc(port, edid);

  if(!chk_edid_info(edid)) {
    printf("Port %u: no monitor info [err 0x%04x]\n\n", port, u);
    return;
  }

#if 0
  for(i = 0; i < sizeof edid/sizeof *edid; i++) {
    printf(" 0x%02x", edid[i]);
    if(i % 8 == 7) printf("\n");
  }
#endif

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

  printf("\n");
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


char *canon_str(char *s, int len)
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


unsigned probe_ddc(int port, unsigned char *edid)
{
  x86regs_t r = { };

  memset(edid, 0, 0x80);

  r.eax = 0x4f15;
  r.ebx = 1;
  r.ecx = port;
  r.edi = (unsigned) edid;

  x86int(0x10, &r);

  // failed
  if(r.eax != 0x004f) memset(edid, 0, 0x80);

  return r.eax;
}

