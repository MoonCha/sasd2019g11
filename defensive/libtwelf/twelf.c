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

// start, end: exclusively
// assume: a_start <= a_end && b_start <= b_end
bool is_overlap(uint64_t a_start, uint64_t a_end, uint64_t b_start, uint64_t b_end) {
  return a_start < b_end && b_start < a_end;
}
bool is_partial_overlap(uint64_t a_start, uint64_t a_end, uint64_t b_start, uint64_t b_end) {
  return is_overlap(a_start, a_end, b_start, b_end) && !((a_start <= b_start && b_end <= a_end) || (b_start <= a_start && a_end <= b_end));
}

int libtwelf_open(char *path, struct LibtwelfFile **result)
{
  int return_code = SUCCESS;

  // need resource management
  int fd = -1;
  size_t file_size;
  char *mmaped_file = MAP_FAILED;
  struct LibtwelfSegment *segment_table = NULL;
  Elf64_Off (*pt_load_segment_boundary_table)[2] = NULL;
  struct LibtwelfSection *section_table = NULL;
  char *file_name = NULL;
  struct LibtwelfFileInternal *twelf_file_internal = NULL;
  struct LibtwelfFile *twelf_file = NULL;

  // open and read file
  fd = open(path, O_RDONLY);
  if (fd == -1) {
    log_info("fd error");
    return_code = ERR_IO;
    goto fail;
  }
  struct stat file_stat;
  if (fstat(fd, &file_stat)) {
    log_info("fstat error");
    return_code = ERR_IO;
    goto fail;
  }
  file_size = (size_t)file_stat.st_size;
  if (file_size < sizeof(Elf64_Ehdr)) {
    log_info("file size too small");
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }
  mmaped_file = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (mmaped_file == MAP_FAILED) {
    log_info("mmap error");
    return_code = ERR_IO;
    goto fail;
  }

  // ehdr check validity
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)mmaped_file;
  log_info("sizeof(Elf64_Ehdr): %lu", sizeof(Elf64_Ehdr));
  if (memcmp(&ehdr->e_ident, "\x7f\x45\x4c\x46\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00", 16) != 0
   || ehdr->e_version != EV_CURRENT
   || ehdr->e_ehsize != 64
   || ehdr->e_phentsize != 56
   || ehdr->e_shentsize != 64
   || ehdr->e_phoff >= file_size
   || ehdr->e_shoff >= file_size
   || (ehdr->e_shnum > 0 && ehdr->e_shstrndx >= ehdr->e_shnum)
  ) {
    log_info("general ehdr values are not valid");
    log_info("ehdr->e_version: %u", ehdr->e_version);
    log_info("ehdr->e_ehsize: %u", ehdr->e_ehsize);
    log_info("ehdr->e_phentsize: %u", ehdr->e_phentsize);
    log_info("ehdr->e_shentsize: %u", ehdr->e_shentsize);
    log_info("ehdr->e_phoff: %lu", ehdr->e_phoff);
    log_info("ehdr->e_shoff: %lu", ehdr->e_shoff);
    log_info("ehdr->shstrndx: %u", ehdr->e_shstrndx);
    log_info("ehdr->e_shnum: %u", ehdr->e_shnum);
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }
  Elf64_Off shdr_table_end;
  if (__builtin_mul_overflow(ehdr->e_shnum, ehdr->e_shentsize, &shdr_table_end)
   || __builtin_add_overflow(ehdr->e_shoff, shdr_table_end, &shdr_table_end)) {
     log_info("shdr_table_end calcuation overflow");
     return_code = ERR_ELF_FORMAT;
     goto fail;
  }
  log_info("shdr_table_end: %lx", shdr_table_end);
  if (shdr_table_end > file_size) {
    log_info("shdr_table_end exceeds file_size");
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }
  Elf64_Off phdr_table_end;
  if (__builtin_mul_overflow(ehdr->e_phnum, ehdr->e_phentsize, &phdr_table_end)
   || __builtin_add_overflow(ehdr->e_phoff, phdr_table_end, &phdr_table_end)) {
     log_info("phdr_table_end calcuation overflow");
     return_code = ERR_ELF_FORMAT;
     goto fail;
  }
  log_info("phdr_table_end: %lx", phdr_table_end);
  if (phdr_table_end > file_size) {
    log_info("phdr_table_end exceeds file_size");
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }

  // create segement table with validation
  segment_table = (struct LibtwelfSegment *)calloc(sizeof(struct LibtwelfSegment), ehdr->e_phnum);
  if (segment_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  pt_load_segment_boundary_table = (Elf64_Off (*)[2])calloc(sizeof(Elf64_Off) * 2, ehdr->e_phnum);
  if (pt_load_segment_boundary_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  Elf64_Off last_pt_load_phdr_vaddr = 0;
  Elf64_Xword last_pt_load_phdr_vaddr_end = 0;
  for (size_t i = 0; i < ehdr->e_phnum; ++i) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)(((uintptr_t)mmaped_file + ehdr->e_phoff) + i * ehdr->e_phentsize);
    // phdr validity check
    Elf64_Off segment_end;
    uint64_t segment_vaddr_end;
    if (phdr->p_offset >= file_size
     || __builtin_add_overflow(phdr->p_offset, phdr->p_filesz, &segment_end)
     || segment_end > file_size
     || phdr->p_filesz > phdr->p_memsz
     || (phdr->p_align & (phdr->p_align - 1)) != 0
     || __builtin_add_overflow(phdr->p_vaddr, phdr->p_memsz, &segment_vaddr_end)
    ) {
      log_info("phdr(index: %lu) is invalid", i);
      log_info("phdr->p_align: %lu", phdr->p_align);
      return_code = ERR_ELF_FORMAT;
      goto fail;
    }
    if (phdr->p_type == PT_LOAD) {
      if (phdr->p_vaddr < last_pt_load_phdr_vaddr
       || is_overlap(phdr->p_vaddr, phdr->p_vaddr + phdr->p_memsz, last_pt_load_phdr_vaddr, last_pt_load_phdr_vaddr_end)
      ) {
        log_info("PT_LOAD type phdr is not sorted by p_vaddr or overlapped");
        return_code = ERR_ELF_FORMAT;
        goto fail;
      }
      log_info("phdr vaddr range(index: %lu): [0x%lx, 0x%lx]", i, phdr->p_vaddr, segment_vaddr_end);
      last_pt_load_phdr_vaddr = phdr->p_vaddr;
      last_pt_load_phdr_vaddr_end = segment_vaddr_end;
      pt_load_segment_boundary_table[i][0] = phdr->p_vaddr;
      pt_load_segment_boundary_table[i][1] = segment_vaddr_end;
    }
    // update segment_table entry
    struct LibtwelfSegment *twelf_segment = &segment_table[i];
    log_info("twelf_segment(%lu): %p", i, twelf_segment);
    twelf_segment->internal = (struct LibtwelfSegmentInternal *)calloc(sizeof(struct LibtwelfSegmentInternal), 1);
    if (twelf_segment->internal == NULL) {
      log_info("calloc error");
      return_code = ERR_NOMEM;
      goto fail;
    }
    twelf_segment->internal->p_offset = phdr->p_offset;
    twelf_segment->internal->p_paddr = phdr->p_paddr;
    twelf_segment->internal->p_align = phdr->p_align;

    twelf_segment->type = phdr->p_type;
    twelf_segment->vaddr = phdr->p_vaddr;
    twelf_segment->filesize = phdr->p_filesz;
    twelf_segment->memsize = phdr->p_memsz;
    twelf_segment->readable = phdr->p_flags & PF_R;
    twelf_segment->writeable = phdr->p_flags & PF_W;
    twelf_segment->executable = phdr->p_flags & PF_X;
  }

  // create section table with validation
  section_table = (struct LibtwelfSection *)calloc(sizeof(struct LibtwelfSection), ehdr->e_shnum);
  if (section_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  Elf64_Shdr *shstr_shdr = (Elf64_Shdr *)(((uintptr_t)mmaped_file + ehdr->e_shoff) + ehdr->e_shstrndx * ehdr->e_shentsize);
  for (size_t i = 0; i < ehdr->e_shnum; ++i) {
    Elf64_Shdr *shdr = (Elf64_Shdr *)(((uintptr_t)mmaped_file + ehdr->e_shoff) + i * ehdr->e_shentsize);
    log_info("shdr->sh_entsize: %lu", shdr->sh_entsize);
    // shdr validity check
    Elf64_Off section_end;
    uint64_t section_vaddr_end;
    if (shdr->sh_name >= shstr_shdr->sh_size
     || shdr->sh_offset >= file_size
     || __builtin_add_overflow(shdr->sh_offset, shdr->sh_size, &section_end)
     || section_end > file_size
     || shdr->sh_link >= ehdr->e_shnum
     || (shdr->sh_addralign & (shdr->sh_addralign - 1)) != 0
     || __builtin_add_overflow(shdr->sh_addr, shdr->sh_size, &section_vaddr_end)
    ) {
      log_info("shdr(index: %lu) is invalid", i);
      log_info("shdr->sh_addralign: %lu", shdr->sh_addralign);
      return_code = ERR_ELF_FORMAT;
      goto fail;
    }
    for (size_t j = 0; j < ehdr->e_phnum; ++j) {
      if (is_partial_overlap(shdr->sh_addr, section_vaddr_end, pt_load_segment_boundary_table[j][0], pt_load_segment_boundary_table[j][1])) {
        log_info("section(index: %lu) paritally overlap with segment(index: %lu)", i, j);
        return_code = ERR_ELF_FORMAT;
        goto fail;
      }
    }
    if (i == 0 && shdr->sh_type != SHT_NULL) {
      log_info("first shdr is not SHT_NULL type");
      return_code = ERR_ELF_FORMAT;
      goto fail;
    }
    // update section_table entry
    struct LibtwelfSection *twelf_section = &section_table[i];
    log_info("twelf_section(%lu): %p", i, twelf_section);
    twelf_section->internal = (struct LibtwelfSectionInternal *)calloc(sizeof(struct LibtwelfSectionInternal), 1);
    if (twelf_section->internal == NULL) {
      log_info("calloc error");
      return_code = ERR_NOMEM;
      goto fail;
    }
    twelf_section->internal->section_data = (char *)malloc(shdr->sh_size + 1); // 1 for preventing zero-size allocation
    if (twelf_section->internal->section_data == NULL) {
      log_info("malloc error");
      return_code = ERR_NOMEM;
      goto fail;
    }
    char *section_data = (char *)((uintptr_t)mmaped_file + shdr->sh_offset);
    memcpy(twelf_section->internal->section_data, section_data, shdr->sh_size);
    twelf_section->internal->sh_addralign = shdr->sh_addralign;
    twelf_section->internal->sh_entsize = shdr->sh_entsize;
    twelf_section->internal->sh_link = shdr->sh_link;
    twelf_section->internal->sh_info = shdr->sh_info;
    twelf_section->internal->sh_offset = shdr->sh_offset; // TODO: remove?
    twelf_section->internal->sh_name = shdr->sh_name;
    twelf_section->name = (char *)((uintptr_t)mmaped_file + shstr_shdr->sh_offset + shdr->sh_name);
    twelf_section->address = shdr->sh_addr;
    twelf_section->size = shdr->sh_size;
    twelf_section->type = shdr->sh_type;
    twelf_section->flags = shdr->sh_flags;
    twelf_section->link = &section_table[shdr->sh_link];
  }

  // replicate path
  size_t file_name_buffer_length = strlen(path) + 1;
  file_name = (char *)malloc(file_name_buffer_length);
  if (file_name == NULL) {
    log_info("malloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  strncpy(file_name, path, file_name_buffer_length);

  // create internal
  twelf_file_internal = (struct LibtwelfFileInternal *)malloc(sizeof(struct LibtwelfFileInternal));
  if (twelf_file_internal == NULL) {
    log_info("malloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  twelf_file_internal->mmap_size = file_size;
  twelf_file_internal->mmap_base = mmaped_file;

  // assemble LibtwelfFile and update result
  twelf_file = (struct LibtwelfFile *)malloc(sizeof(struct LibtwelfFile));
  if (twelf_file == NULL) {
    log_info("malloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  twelf_file->number_of_sections = ehdr->e_shnum;
  twelf_file->section_table = section_table;
  twelf_file->number_of_segments = ehdr->e_phnum;
  twelf_file->segment_table = segment_table;
  twelf_file->file_name = file_name;
  twelf_file->internal = twelf_file_internal;
  *result = twelf_file;

  // clean up
  free(pt_load_segment_boundary_table);
  close(fd);
  log_info("Success");
  return return_code;

  fail:
  if (twelf_file != NULL) {
    free(twelf_file);
  }
  if (twelf_file_internal != NULL) {
    free(twelf_file_internal);
  }
  if (file_name != NULL)  {
    free(file_name);
  }
  if (section_table != NULL) {
    for (size_t i = 0; i < ehdr->e_shnum; ++i) {
      struct LibtwelfSection *twelf_section = &section_table[i];
      if (twelf_section->internal != NULL) {
        if (twelf_section->internal->section_data != NULL) {
          free(twelf_section->internal->section_data);
        }
        free(twelf_section->internal);
      }
    }
    free(section_table);
  }
  if (pt_load_segment_boundary_table != NULL) {
    free(pt_load_segment_boundary_table);
  }
  if (segment_table != NULL) {
    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
      struct LibtwelfSegment *twelf_segment = &segment_table[i];
      if (twelf_segment->internal != NULL) {
        free(twelf_segment->internal);
      }
    }
    free(segment_table);
  }
  if (mmaped_file != MAP_FAILED) {
    munmap(mmaped_file, file_size);
  }
  if (fd != -1) {
    close(fd);
  }
  if (return_code == SUCCESS) {
    log_warn("Fail with SUCCESS");
  } else {
    log_info("Fail: %d", return_code);
  }
  return return_code;
}

void libtwelf_close(struct LibtwelfFile *twelf)
{
  free(twelf->file_name);
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *twelf_section = &twelf->section_table[i];
    free(twelf_section->internal->section_data);
    free(twelf_section->internal);
  }
  free(twelf->section_table);
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
    free(twelf_segment->internal);
  }
  free(twelf->segment_table);
  munmap(twelf->internal->mmap_base, twelf->internal->mmap_size);
  free(twelf->internal);
  free(twelf);
}

int libtwelf_getSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char **data, size_t *len)
{
  (void) twelf;
  if (section->type == SHT_NOBITS) {
    *len = 0;
    *data = NULL;
    return SUCCESS;
  }
  // TODO: remove?
  // *data = (char *)((uintptr_t)twelf->internal->mmap_base + section->internal->sh_offset);
  *data = section->internal->section_data;
  *len = section->size;
  return SUCCESS;
}

int libtwelf_getSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char **data, size_t *filesz, size_t *memsz)
{
  (void) twelf;
  // TODO: remove?
  *data = (char *)((uintptr_t)twelf->internal->mmap_base + segment->internal->p_offset);
  *filesz = segment->filesize;
  *memsz = segment->memsize;
  return SUCCESS;
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
  // offset. (or in mathematical terms: virtual_address % PAGE_SIZE == p_offset % PAGE_SIZE)
  //
  // Also, sections must be aligned corresponding to the alignment specification
  // in their header.
  //
  // To start off you can try writing segment data and section data separately.
  // As segments are groups of sections, they tend to overlap in the input file.
  // When writing the output file you should not write data twice  to achieve
  // full points. (for example if the data of the .text section is also part of
  // a PT_LOAD segment)
  int return_value = SUCCESS;
  // need resource management
  FILE *outfile = NULL;
  Elf64_Off (*segment_boundary_table)[2] = NULL;
  Elf64_Phdr *phdr_table = NULL;
  Elf64_Shdr *shdr_table = NULL;
  char *data_buffer = NULL;
  size_t file_size_wo_section_info = sizeof(Elf64_Ehdr);

  outfile = fopen(dest_file, "wb");
  if (outfile == NULL) {
    log_info("fopen error");
    return_value = ERR_IO;
    goto fail;
  }
  // reconstruct phdr
  segment_boundary_table = (Elf64_Off (*)[2])calloc(sizeof(Elf64_Off) * 2, twelf->number_of_segments);
  if (segment_boundary_table == NULL) {
    log_info("calloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  if (twelf->number_of_segments > 0) {
    phdr_table = (Elf64_Phdr *)calloc(sizeof(Elf64_Phdr), twelf->number_of_segments);
    if (phdr_table == NULL) {
      log_info("calloc error");
      return_value = ERR_NOMEM;
      goto fail;
    }
    for (size_t i = 0; i < twelf->number_of_segments; ++i) {
      Elf64_Phdr *segment = &phdr_table[i];
      struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
      if (twelf_segment->type == PT_LOAD) {
        segment_boundary_table[i][0] = twelf_segment->vaddr;
        segment_boundary_table[i][1] = twelf_segment->vaddr + twelf_segment->memsize; // overflow checked by open & modification functions
      }
      uint64_t segment_end_on_file = twelf_segment->internal->p_offset + twelf_segment->filesize;
      if (segment_end_on_file > file_size_wo_section_info) { // overflow checked by open & modification functions
        file_size_wo_section_info = segment_end_on_file;
      }
      Elf64_Word flag = 0;
      flag |= twelf_segment->readable ? PF_R : 0;
      flag |= twelf_segment->writeable ? PF_W : 0;
      flag |= twelf_segment->executable ? PF_X : 0;
      segment->p_type = twelf_segment->type;
      segment->p_flags = flag;
      segment->p_offset = twelf_segment->internal->p_offset;
      segment->p_vaddr = twelf_segment->vaddr;
      segment->p_paddr = twelf_segment->internal->p_paddr;
      segment->p_filesz = twelf_segment->filesize;
      segment->p_memsz = twelf_segment->memsize;
      segment->p_align = twelf_segment->internal->p_align;
      log_info("segment->p_type(index: %lu): %u", i, segment->p_type);
      log_info("segment->p_flags(index: %lu): %u", i, segment->p_flags);
      log_info("segment->p_offset(index: %lu): %lu", i, segment->p_offset);
      log_info("segment->p_vaddr(index: %lu): %lu", i, segment->p_vaddr);
      log_info("segment->p_paddr(index: %lu): %lu", i, segment->p_paddr);
      log_info("segment->p_filesz(index: %lu): %lu", i, segment->p_filesz);
      log_info("segment->p_memsz(index: %lu): %lu", i, segment->p_memsz);
      log_info("segment->p_align(index: %lu): %lu", i, segment->p_align);
    }
  }
  // TODO: reconstruct shdr and also data if no associated segment exists
  if (twelf->number_of_sections > 0) {
    shdr_table = (Elf64_Shdr *)calloc(sizeof(Elf64_Shdr), twelf->number_of_sections);
    if (shdr_table == NULL) {
      log_info("calloc error");
      return_value = ERR_NOMEM;
      goto fail;
    }
    for (size_t i = 0; i < twelf->number_of_sections; ++i) {
      Elf64_Shdr *section = &shdr_table[i];
      struct LibtwelfSection *twelf_section = &twelf->section_table[i];
      section->sh_name = twelf_section->internal->sh_name;
      section->sh_type = twelf_section->type;
      section->sh_flags = twelf_section->flags;
      section->sh_addr = twelf_section->address;
      section->sh_offset = twelf_section->internal->sh_offset;
      section->sh_size = twelf_section->size;
      section->sh_link = twelf_section->internal->sh_link;
      section->sh_info = twelf_section->internal->sh_info;
      section->sh_addralign = twelf_section->internal->sh_addralign;
      section->sh_entsize = twelf_section->internal->sh_entsize;
      log_info("section->sh_name(index: %lu): %u", i, section->sh_name);
      log_info("section->sh_type(index: %lu): %u", i, section->sh_type);
      log_info("section->sh_flags(index: %lu): %lu", i, section->sh_flags);
      log_info("section->sh_addr(index: %lu): %lu", i, section->sh_addr);
      log_info("section->sh_offset(index: %lu): %lu", i, section->sh_offset);
      log_info("section->sh_size(index: %lu): %lu", i, section->sh_size);
      log_info("section->sh_link(index: %lu): %u", i, section->sh_link);
      log_info("section->sh_info(index: %lu): %u", i, section->sh_info);
      log_info("section->sh_addralign(index: %lu): %lu", i, section->sh_addralign);
      log_info("section->sh_entsize(index: %lu): %lu", i, section->sh_entsize);
    }
  }
  // TODO: move reconstruct ehdr to add segment
  /*
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)twelf->internal->mmap_base;
  ehdr->e_phoff = twelf->number_of_segments > 0 ? sizeof(Elf64_Ehdr) : 0;
  // ehdr->e_shoff = NULL;
  */

  // write back
  /*
  if (fseek(header_total_size, 0, SEEK_SET)) {
    return_value = ERR_IO;
    goto fail;
  }
  */
  if (twelf->internal->mmap_size < file_size_wo_section_info) {
    log_warn("FATAL ERROR: wrong implementation somewhere");
  }
  if (fwrite(twelf->internal->mmap_base, 1, file_size_wo_section_info, outfile) < file_size_wo_section_info) {
    return_value = ERR_IO;
    goto fail;
  }
  // clean resources
  free(data_buffer);
  free(shdr_table);
  free(phdr_table);
  free(segment_boundary_table);
  fclose(outfile);
  return return_value;
  fail:
  if (data_buffer != NULL) {
    free(data_buffer);
  }
  if (shdr_table != NULL) {
    free(shdr_table);
  }
  if (phdr_table != NULL) {
    free(phdr_table);
  }
  if (segment_boundary_table != NULL) {
    free(segment_boundary_table);
  }
  if (outfile != NULL) {
    fclose(outfile);
  }
  return return_value;
}

int libtwelf_getAssociatedSegment(struct LibtwelfFile *twelf, struct LibtwelfSection *section, struct LibtwelfSegment **result)
{
  uint64_t section_start = section->address;
  uint64_t section_end = section->address + section->size;
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *segment = &twelf->segment_table[i];
    if (segment->type == PT_LOAD && segment->vaddr <= section_start && section_end <= segment->vaddr + segment->memsize) {
      *result = segment;
      return SUCCESS;
    }
  }
  return ERR_NOT_FOUND;
}

int libtwelf_resolveSymbol(struct LibtwelfFile *twelf, const char *name, Elf64_Addr *st_value)
{
  (void) twelf;
  (void) name;
  (void) st_value;
  bool symtab_found = false;
  const char *symtab_section_data;
  const char *strtab_section_data;
  size_t symtab_section_size = 0;
  size_t strtab_section_size = 0;
  Elf64_Xword entsize = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    if (strcmp(section->name, ".symtab") == 0) {
      entsize = section->internal->sh_entsize;
      libtwelf_getSectionData(twelf, section, &symtab_section_data, &symtab_section_size);
      libtwelf_getSectionData(twelf, section->link, &strtab_section_data, &strtab_section_size);
      symtab_found = true;
      break;
    }
  }
  if (!symtab_found) {
    return ERR_ELF_FORMAT;
  }
  log_info("symtab_section_size: %lu, entsize: %lu, sizeof(Elf64_Sym): %lu", symtab_section_size, entsize, sizeof(Elf64_Sym));
  size_t symbol_size = entsize >= sizeof(Elf64_Sym) ? entsize : sizeof(Elf64_Sym);
  size_t symbol_count = symtab_section_size / sizeof(Elf64_Sym);
  for (size_t i = 0; i < symbol_count; ++i) {
    Elf64_Sym *symbol = (Elf64_Sym *)((uintptr_t)symtab_section_data + i * symbol_size);
    // TODO: when to check st_name validity?: resolveSymbol or open
    if (symbol->st_name >= strtab_section_size) {
      continue;
    }
    if (strcmp(name, strtab_section_data + symbol->st_name) == 0) {
      *st_value = symbol->st_value;
      return SUCCESS;
    }
  }
  return ERR_NOT_FOUND;
}

int libtwelf_addSymbol(struct LibtwelfFile *twelf, struct LibtwelfSection* section, const char *name, unsigned char type, Elf64_Addr st_value)
{
  (void) twelf;
  (void) section;
  (void) name;
  (void) type;
  (void) st_value;
  return ERR_NOT_IMPLEMENTED;
}
