/*
  linker script for standalone program
 */

OUTPUT_FORMAT("binary")
OUTPUT_ARCH(i386)
SEARCH_DIR(".")
ENTRY(_start)
SECTIONS
{
  .init   : { *(.init) }
  .text   : { *(.text) }
  .rodata : { *(.rodata*) }
  .data   : { *(.data) }
  .bss    : { *(.bss) }
}
