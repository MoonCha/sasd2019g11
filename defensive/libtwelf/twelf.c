////////////////////////////////////////////////////////////////////////////////
//
// for reference on ELF file format see
// * man elf
// * https://lwn.net/Articles/276782/
// * https://en.wikipedia.org/wiki/Executable_and_Linkable_Format
// * https://en.wikipedia.org/wiki/File:ELF_Executable_and_Linkable_Format_diagram_by_Ange_Albertini.png
//
////////////////////////////////////////////////////////////////////////////////

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <twelf.h>
#include <errno.h>

#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>

#include "libtwelf.h"
#include "libtwelf_types.h"
#include "internal_types.h"

#include "util.h"

#define free_null(x) ({free(x); x = NULL;})

static int readSegments(struct LibtwelfFile *elf);
static int readSections(struct LibtwelfFile *elf);

int libtwelf_open(char *path, struct LibtwelfFile **result)
{
  (void) path;
  (void) result;
  return ERR_NOT_IMPLEMENTED;
}



void libtwelf_close(struct LibtwelfFile *twelf)
{
  (void) twelf;
}

int libtwelf_getSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char **data, size_t *len)
{
  (void) twelf;
  (void) section;
  (void) data;
  (void) len;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_getSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char **data, size_t *filesz, size_t *memsz)
{
  (void) twelf;
  (void) segment;
  (void) data;
  (void) filesz;
  (void) memsz;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_setSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char *data, size_t filesz, size_t memsz)
{
  (void) twelf;
  (void) segment;
  (void) data;
  (void) filesz;
  (void) memsz;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_setSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *data, size_t size)
{
  (void) twelf;
  (void) section;
  (void) data;
  (void) size;
  return ERR_NOT_IMPLEMENTED;
}



int libtwelf_renameSection(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *name_arg)
{
  (void) twelf;
  (void) section;
  (void) name_arg;
  return ERR_NOT_IMPLEMENTED;
}



int libtwelf_stripSymbols(struct LibtwelfFile *twelf)
{
  // keep in mind to adjust the sh_link values (and the link pointers) for all
  // remaining sections as they may need to be updated
  (void) twelf;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_removeAllSections(struct LibtwelfFile *twelf)
{
  (void) twelf;
  return ERR_NOT_IMPLEMENTED;
}


int libtwelf_addLoadSegment(struct LibtwelfFile *twelf, char *data, size_t len, uint32_t flags, Elf64_Addr vaddr)
{
  (void) twelf;
  (void) data;
  (void) len;
  (void) flags;
  (void) vaddr;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_write(struct LibtwelfFile *twelf, char *dest_file)
{
  // Keep in mind the alignment requirements when implementing this function
  // each PT_LOAD segment's start address's page offset must equal the file offset's page
  // offset. (or in mathematical terms: virtual_address % PAGE_SIZE == ph_off % PAGE_SIZE)
  //
  // Also, sections must be aligned corresponding to the alignment specification
  // in their header.
  //
  // To start off you can try writing segment data and section data separately.
  // As segments are groups of sections, they tend to overlap in the input file.
  // When writing the output file you should not write data twice  to achieve
  // full points. (for example if the data of the .text section is also part of
  // a PT_LOAD segment)
  (void) twelf;
  (void) dest_file;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_getAssociatedSegment(struct LibtwelfFile *twelf, struct LibtwelfSection *section, struct LibtwelfSegment **result)
{
  (void) twelf;
  (void) section;
  (void) result;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_resolveSymbol(struct LibtwelfFile *twelf, const char *name, Elf64_Addr *st_value)
{
  (void) twelf;
  (void) name;
  (void) st_value;
  return ERR_NOT_IMPLEMENTED;
}

int libtwelf_addSymbol(struct LibtwelfFile *twelf, struct LibtwelfSection* section, const char *name, unsigned char st_info, Elf64_Addr st_value)
{
  (void) twelf;
  (void) section;
  (void) name;
  (void) st_info;
  (void) st_value;
  return ERR_NOT_IMPLEMENTED;
}
