////////////////////////////////////////////////////////////////////////////////
// shortened elf.h from the glibc
// https://sourceware.org/git/?p=glibc.git;a=blob;f=elf/elf.h;h=69ffa2ec0e0765057620b599d5de7ea2aa8bd32d;hb=HEAD
// original comments are multiline: /* */
// added comments are single line: //
//
// DO NOT MODIFY THIS FILE
////////////////////////////////////////////////////////////////////////////////

/* This file defines standard ELF types, structures, and macros.
   Copyright (C) 1995-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.

   The GNU C Library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   The GNU C Library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

   You should have received a copy of the GNU Lesser General Public
   License along with the GNU C Library; if not, see
   <http://www.gnu.org/licenses/>.  */

#ifndef _TWELF_H
#define _TWELF_H 1

/* Standard ELF types.  */

#include <stdint.h>

/* Type for a 16-bit quantity.  */
typedef uint16_t Elf32_Half;
typedef uint16_t Elf64_Half;

/* Types for signed and unsigned 32-bit quantities.  */
typedef uint32_t Elf32_Word;
typedef int32_t Elf32_Sword;
typedef uint32_t Elf64_Word;
typedef int32_t Elf64_Sword;

/* Types for signed and unsigned 64-bit quantities.  */
typedef uint64_t Elf32_Xword;
typedef int64_t Elf32_Sxword;
typedef uint64_t Elf64_Xword;
typedef int64_t Elf64_Sxword;

/* Type of addresses.  */
typedef uint32_t Elf32_Addr;
typedef uint64_t Elf64_Addr;

/* Type of file offsets.  */
typedef uint32_t Elf32_Off;
typedef uint64_t Elf64_Off;

/* Type for section indices, which are 16-bit quantities.  */
typedef uint16_t Elf32_Section;
typedef uint16_t Elf64_Section;

/* Type for version symbol information.  */
typedef Elf32_Half Elf32_Versym;
typedef Elf64_Half Elf64_Versym;


/* The ELF file header.  This appears at the start of every ELF file.  */

#define EI_NIDENT (16)

// This struct contains the file header for elf files. All comments must be checked during libtwelf_open.
// libtwelf_write should retain the values of the original file (unless the value was updated by another libtwelf function).
typedef struct
{
  unsigned char e_ident[EI_NIDENT]; /* Magic number and other info */         // must be "\x7fELF\x02\x01\x01" padded with zeros to the right
  Elf64_Half e_type;                /* Object file type */
  Elf64_Half e_machine;             /* Architecture */
  Elf64_Word e_version;             /* Object file version */                 // must be EV_CURRENT
  Elf64_Addr e_entry;               /* Entry point virtual address */
  Elf64_Off e_phoff;                /* Program header table file offset */    // must be within file (including size of the table)
  Elf64_Off e_shoff;                /* Section header table file offset */    // must be within file (including size of the table)
  Elf64_Word e_flags;               /* Processor-specific flags */
  Elf64_Half e_ehsize;              /* ELF header size in bytes */            // must be 64
  Elf64_Half e_phentsize;           /* Program header table entry size */     // must be 56
  Elf64_Half e_phnum;               /* Program header table entry count */
  Elf64_Half e_shentsize;           /* Section header table entry size */     // must be 64
  Elf64_Half e_shnum;               /* Section header table entry count */
  Elf64_Half e_shstrndx;            /* Section header string table index */   // index of the .shstrtab section (must be valid unless there are no sections at all)
} Elf64_Ehdr;

/* Fields in the e_ident array.  The EI_* macros are indices into the
   array.  The macros under each EI_* macro are the values the byte
   may have.  */

#define EI_MAG0 0    /* File identification byte 0 index */
#define ELFMAG0 0x7f /* Magic number byte 0 */

#define EI_MAG1 1   /* File identification byte 1 index */
#define ELFMAG1 'E' /* Magic number byte 1 */

#define EI_MAG2 2   /* File identification byte 2 index */
#define ELFMAG2 'L' /* Magic number byte 2 */

#define EI_MAG3 3   /* File identification byte 3 index */
#define ELFMAG3 'F' /* Magic number byte 3 */

/* Conglomeration of the identification bytes, for easy testing as a word.  */
#define ELFMAG "\177ELF"
#define SELFMAG 4

#define EI_CLASS 4     /* File class byte index */
#define ELFCLASS64 2   /* 64-bit objects */

#define EI_DATA 5     /* Data encoding byte index */
#define ELFDATA2LSB 1 /* 2's complement, little endian */

#define EI_VERSION 6 /* File version byte index */
                     /* Value must be EV_CURRENT */

#define EI_OSABI 7
#define ELFOSABI_SYSV 0

/* Legal values for e_version (version).  */

#define EV_CURRENT 1 /* Current version */

/* Section header.  */

// This struct contains one entry of the section header table. All comments must be checked during libtwelf_open.
// this struct is located in the elf file at offset Elf64_Ehdr.e_shoff
// the .shstrtab section is the section with index Elf64_Ehdr.e_shstrndx
// When writing a file, the segment data must be aligned by Elf64_Shdr.sh_entsize
typedef struct
{
  Elf64_Word sh_name;       /* Section name (string tbl index) */     // index into the .shstrtab section (must be valid)
  Elf64_Word sh_type;       /* Section type */
  Elf64_Xword sh_flags;     /* Section flags */
  Elf64_Addr sh_addr;       /* Section virtual addr at execution */
  Elf64_Off sh_offset;      /* Section file offset */                 // must be within elf file (including size)
  Elf64_Xword sh_size;      /* Section size in bytes */
  Elf64_Word sh_link;       /* Link to another section */             // must be valid index of another section
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */                   // must be a power of 2, when writing a file section data must be aligned by this value
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
} Elf64_Shdr;

/* Special section indices.  */

#define SHN_UNDEF 0          /* Undefined section */                   // the section at index 0 must always be of type SHT_NULL

/* Legal values for sh_type (section type).  */

#define SHT_NULL 0                    /* Section header table entry unused */
#define SHT_PROGBITS 1                /* Program data */
#define SHT_SYMTAB 2                  /* Symbol table */
#define SHT_STRTAB 3                  /* String table */
#define SHT_NOBITS 8                  /* Program space with no data (bss) */  // the content of sections with this type will not be written to file

/* Legal values for sh_flags (section flags).  */

#define SHF_ALLOC (1 << 1)      /* Occupies memory during execution */


/* Program segment header.  */

// This struct contains one entry of the program header table (a segment header). All comments must be checked during libtwelf_open.
// When writing a file, the segment data must be aligned by Elf64_Phdr.p_align
typedef struct
{
  Elf64_Word p_type;    /* Segment type */
  Elf64_Word p_flags;   /* Segment flags */
  Elf64_Off p_offset;   /* Segment file offset */          // must be within elf file (including p_filesz)
  Elf64_Addr p_vaddr;   /* Segment virtual address */      // all PT_LOAD segments must be sorted using this field
  Elf64_Addr p_paddr;   /* Segment physical address */
  Elf64_Xword p_filesz; /* Segment size in file */         // must not be larger than p_memsz
  Elf64_Xword p_memsz;  /* Segment size in memory */
  Elf64_Xword p_align;  /* Segment alignment */            // must be a power of 2
} Elf64_Phdr;

/* Legal values for p_type (segment type).  */

#define PT_NULL 0                  /* Program header table entry unused */
#define PT_LOAD 1                  /* Loadable program segment */
#define PT_DYNAMIC 2               /* Dynamic linking information */
#define PT_NOTE 4                  /* Auxiliary information */
#define PT_TLS 7                   /* Thread-local storage segment */
#define PT_GNU_STACK 0x6474e551    /* Indicates stack executability */

/* Legal values for p_flags (segment flags).  */

#define PF_X (1 << 0)          /* Segment is executable */
#define PF_W (1 << 1)          /* Segment is writable */
#define PF_R (1 << 2)          /* Segment is readable */



/* Symbol table entry.  */

typedef struct
{
  Elf64_Word st_name;     /* Symbol name (string tbl index) */
  unsigned char st_info;  /* Symbol type and binding */
  unsigned char st_other; /* Symbol visibility */
  Elf64_Section st_shndx; /* Section index */
  Elf64_Addr st_value;    /* Symbol value */
  Elf64_Xword st_size;    /* Symbol size */
} Elf64_Sym;

/* How to extract and insert information held in the st_info field.  */

#define ELF32_ST_BIND(val) (((unsigned char) (val)) >> 4)
#define ELF32_ST_TYPE(val) ((val) &0xf)
#define ELF32_ST_INFO(bind, type) (((bind) << 4) + ((type) &0xf))

/* Both Elf32_Sym and Elf64_Sym use the same one-byte st_info field.  */
#define ELF64_ST_BIND(val) ELF32_ST_BIND(val)
#define ELF64_ST_TYPE(val) ELF32_ST_TYPE(val)
#define ELF64_ST_INFO(bind, type) ELF32_ST_INFO((bind), (type))

/* Legal values for ST_BIND subfield of st_info (symbol binding).  */

#define STB_LOCAL 0       /* Local symbol */
#define STB_GLOBAL 1      /* Global symbol */
#define STB_WEAK 2        /* Weak symbol */

/* Legal values for ST_TYPE subfield of st_info (symbol type).  */

#define STT_NOTYPE 0     /* Symbol type is unspecified */
#define STT_OBJECT 1     /* Symbol is a data object */
#define STT_FUNC 2       /* Symbol is a code object */



#endif /* twelf.h */
