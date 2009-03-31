/*
  linker script for DOS program (.COM)
 */

OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386)
SEARCH_DIR(".")
ENTRY(_start)
SECTIONS
{
  .init 0x100 : { *(.init) }
  .text       : { *(.text) }
  .rodata     : { *(.rodata*) }
  .data       : { *(.data) }
  .bss        : { *(.bss) }
}
