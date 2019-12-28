#pragma once

#include "libtwelf_types.h"

#include <twelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


struct LibtwelfFileInternal
{
  size_t file_size;
  char *mmap_base;
};


struct LibtwelfSegmentInternal
{
  Elf64_Off p_offset;   /* Segment file offset */          // must be within elf file (including p_filesz)
  Elf64_Addr p_paddr;   /* Segment physical address */
  Elf64_Xword p_align;  /* Segment alignment */            // must be a power of 2
};


struct LibtwelfSectionInternal
{
  Elf64_Off sh_offset;      /* Section file offset */                 // must be within elf file (including size)
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */                   // must be a power of 2, when writing a file section data must be aligned by this value
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
};
