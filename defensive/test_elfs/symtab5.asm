BITS 64
org 0x08048000

ehdr:                                ; elf64_ehdr
  db 0x7F, "ELF", 2, 1, 1, 0         ;   e_ident
  db 0, 0, 0, 0, 0, 0, 0, 0
  dw 2                               ;   e_type
  dw 0x3e                            ;   e_machine
  dd 1                               ;   e_version
  dq _start                          ;   e_entry
  dq phdr - $$                       ;   e_phoff
  dq shdr - $$                       ;   e_shoff
  dd 0                               ;   e_flags
  dw ehdrsize                        ;   e_ehsize
  dw phdrsize                        ;   e_phentsize
  dw 2                               ;   e_phnum
  dw shdrsize                        ;   e_shentsize
  dw 5                               ;   e_shnum
  dw 4                               ;   e_shstrndx
ehdrsize      equ     $ - ehdr

phdr:
phdr1:                               ; elf64_phdr
  dd 1                               ;   p_type
  dd 5                               ;   p_flags
  dq segment1 - $$                   ;   p_offset
  dq segment1                        ;   p_vaddr
  dq 0                               ;   p_paddr
  dq segment1size                    ;   p_filesz
  dq segment1size                    ;   p_memsz
  dq 0x1000                          ;   p_align
phdrsize equ $ - phdr

phdr2:                               ; elf64_phdr
  dd 1                               ;   p_type
  dd 5                               ;   p_flags
  dq segment2 - $$                   ;   p_offset
  dq segment2                        ;   p_vaddr
  dq 0                               ;   p_paddr
  dq segment2size                    ;   p_filesz
  dq segment2size                    ;   p_memsz
  dq 0x1000                          ;   p_align

segment1:
  _start:
  xor  eax,eax
  inc  eax
  mov  ebx,eax
  int  0x80
segment1size    equ     $ - segment1

segment2:
  db 1,2,3,4,5,6,7
segment2size    equ     $ - segment2

shstrtab:
  db 0
str_text:
  db ".text", 0
str_shstrtab:
  db ".shstrtab", 0
str_symtab:
  db ".symtab", 0
str_strtab:
  db ".strtab", 0
shstrtabsize equ $ - shstrtab

symtab:
  dd 1      ; st_name
  db 0, 0   ; st_info, st_other
  dw 1      ; st_shndx
  dq 0x1337 ; st_value
  dq 0      ; st_size
symtabsize equ $ - symtab

strtab:
  db 0
str_test:
  db "test", 0
strtabsize equ $ - strtab

align 8;
shdr:
shdr1:                               ; elf64_shdr
  dd 0                               ;   sh_name
  dd 0                               ;   sh_type
  dq 0                               ;   sh_flags
  dq 0                               ;   sh_addr
  dq 0                               ;   sh_offset
  dq 0                               ;   sh_size
  dd 0                               ;   sh_link
  dd 0                               ;   sh_info
  dq 0                               ;   sh_addralign
  dq 0                               ;   sh_entsize
shdrsize equ $ - shdr

shdr2:                               ; elf64_shdr
  dd str_text - shstrtab             ;   sh_name
  dd 1                               ;   sh_type
  dq 6                               ;   sh_flags
  dq segment1                        ;   sh_addr
  dq segment1 - $$                   ;   sh_offset
  dq segment1size                    ;   sh_size
  dd 0                               ;   sh_link
  dd 0                               ;   sh_info
  dq 2                               ;   sh_addralign
  dq 0                               ;   sh_entsize

shdr4:                               ; elf64_shdr
  dd str_symtab - shstrtab           ;   sh_name
  dd 2                               ;   sh_type
  dq 0                               ;   sh_flags
  dq 0                               ;   sh_addr
  dq symtab - $$                     ;   sh_offset
  dq symtabsize                      ;   sh_size
  dd 3                               ;   sh_link
  dd 1                               ;   sh_info ; Index of first non-local symbol
  dq 8                               ;   sh_addralign
  dq 24                              ;   sh_entsize

shdr5:                               ; elf64_shdr
  dd str_strtab - shstrtab           ;   sh_name
  dd 3                               ;   sh_type
  dq 0                               ;   sh_flags
  dq 0                               ;   sh_addr
  dq strtab - $$                     ;   sh_offset
  dq strtabsize                      ;   sh_size
  dd 0                               ;   sh_link
  dd 0                               ;   sh_info
  dq 8                               ;   sh_addralign
  dq 0                               ;   sh_entsize

shdr3:                               ; elf64_shdr
  dd str_shstrtab - shstrtab         ;   sh_name
  dd 3                               ;   sh_type
  dq 0                               ;   sh_flags
  dq 0                               ;   sh_addr
  dq shstrtab - $$                   ;   sh_offset
  dq shstrtabsize                    ;   sh_size
  dd 0                               ;   sh_link
  dd 0                               ;   sh_info
  dq 2                               ;   sh_addralign
  dq 0                               ;   sh_entsize

filesize      equ     $ - $$
