#pragma once

#include "libtwelf_types.h"

#include <twelf.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>


struct LibtwelfFileInternal
{
  size_t file_size;
  char *file_data; // represents whole file only on libtwelf_open, else only represents segment data
};


struct LibtwelfSegmentInternal
{
  size_t index; // index of LibtwelfSegment inside segment_table
  Elf64_Off p_offset;   /* Segment file offset */          // must be within elf file (including p_filesz)
  Elf64_Addr p_paddr;   /* Segment physical address */
  Elf64_Xword p_align;  /* Segment alignment */            // must be a power of 2
};


struct LibtwelfSectionInternal
{
  Elf64_Word sh_name;       /* Section name (string tbl index) */     // index into the .shstrtab section (must be valid)
  Elf64_Off sh_offset;      /* Section file offset */                 // must be within elf file (including size)
  Elf64_Word sh_link;       /* Link to another section */             // must be valid index of another section
  Elf64_Word sh_info;       /* Additional section information */
  Elf64_Xword sh_addralign; /* Section alignment */                   // must be a power of 2, when writing a file section data must be aligned by this value
  Elf64_Xword sh_entsize;   /* Entry size if section holds table */
  char *section_data;
};
