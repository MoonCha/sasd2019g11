BITS 64
org 0x08048000

ehdr:                                ; elf64_ehdr
  db 0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
  db 0, 0, 0, 0, 0, 0, 0, 0
  dw 2                               ;   e_type
  dw 0x3e                            ;   e_machine
  dd 1                               ;   e_version
  dq _start                          ;   e_entry
  dq 0                               ;   e_phoff
  dq 0                               ;   e_shoff
  dd 0                               ;   e_flags
  dw 64                              ;   e_ehsize
  dw 56                              ;   e_phentsize
  dw 0                               ;   e_phnum
  dw 65                              ;   e_shentsize
  dw 0                               ;   e_shnum
  dw 1                               ;   e_shstrndx
ehdrsize      equ     $ - ehdr

_start:

filesize      equ     $ - $$
