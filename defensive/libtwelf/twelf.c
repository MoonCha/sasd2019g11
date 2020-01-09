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
bool section_partially_overlap_segment(uint64_t section_start, uint64_t section_end, uint64_t segment_start, uint64_t segment_end) {
  return is_overlap(section_start, section_end, segment_start, segment_end) && !(segment_start <= section_start && section_end <= segment_end);
}

int libtwelf_open(char *path, struct LibtwelfFile **result)
{
  int return_code = SUCCESS;

  // need resource management
  FILE *file = NULL;
  size_t file_size;
  char *file_data = NULL;
  struct LibtwelfSegment *segment_table = NULL;
  Elf64_Off (*pt_load_segment_boundary_table)[2] = NULL;
  struct LibtwelfSection *section_table = NULL;
  Elf64_Off (*alloc_section_boundary_table)[2] = NULL;
  char *file_name = NULL;
  struct LibtwelfFileInternal *twelf_file_internal = NULL;
  struct LibtwelfFile *twelf_file = NULL;

  // open and read file
  file = fopen(path, "rb");
  if (file == NULL) {
    log_info("fopen error");
    return_code = ERR_IO;
    goto fail;
  }
  if (fseek(file, 0, SEEK_END)) {
    log_info("fseek error");
    return_code = ERR_IO;
    goto fail;
  }
  long ftell_res = ftell(file);
  if (ftell_res == -1) {
    log_info("ftell error");
    return_code = ERR_IO;
    goto fail;
  }
  if (fseek(file, 0, SEEK_SET)) {
    log_info("fseek error");
    return_code = ERR_IO;
    goto fail;
  }
  file_size = (size_t)ftell_res;
  if (file_size < sizeof(Elf64_Ehdr)) {
    log_info("file size too small");
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }
  file_data = (char *)malloc(file_size);
  if (file_data == NULL) {
    log_info("malloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  if (fread(file_data, 1, file_size, file) < file_size) {
    log_info("fread error");
    return_code = ERR_IO;
    goto fail;
  }

  // ehdr check validity
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)file_data;
  log_info("sizeof(Elf64_Ehdr): %lu", sizeof(Elf64_Ehdr));
  log_info("ehdr->e_version: %u", ehdr->e_version);
  log_info("ehdr->e_ehsize: %u", ehdr->e_ehsize);
  log_info("ehdr->e_phentsize: %u", ehdr->e_phentsize);
  log_info("ehdr->e_shentsize: %u", ehdr->e_shentsize);
  log_info("ehdr->e_phoff: %lu", ehdr->e_phoff);
  log_info("ehdr->e_shoff: %lu", ehdr->e_shoff);
  log_info("ehdr->shstrndx: %u", ehdr->e_shstrndx);
  log_info("ehdr->e_phnum: %u", ehdr->e_phnum);
  log_info("ehdr->e_shnum: %u", ehdr->e_shnum);
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
    return_code = ERR_ELF_FORMAT;
    goto fail;
  }
  Elf64_Off shdr_table_end = ehdr->e_shnum * ehdr->e_shentsize;
  if (__builtin_add_overflow(ehdr->e_shoff, shdr_table_end, &shdr_table_end)) {
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
  segment_table = (struct LibtwelfSegment *)calloc(sizeof(struct LibtwelfSegment), ehdr->e_phnum > 0 ? ehdr->e_phnum : 1); // 1 for preventing zero-size allocation
  if (segment_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  pt_load_segment_boundary_table = (Elf64_Off (*)[2])calloc(sizeof(Elf64_Off[2]), ehdr->e_phnum > 0 ? ehdr->e_phnum : 1); // 1 for preventing zero-size allocation
  if (pt_load_segment_boundary_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  Elf64_Off last_pt_load_phdr_vaddr = 0;
  Elf64_Xword last_pt_load_phdr_vaddr_end = 0;
  for (size_t i = 0; i < ehdr->e_phnum; ++i) {
    Elf64_Phdr *phdr = (Elf64_Phdr *)(((uintptr_t)file_data + ehdr->e_phoff) + i * ehdr->e_phentsize);
    // phdr validity check
    Elf64_Off segment_end;
    uint64_t segment_vaddr_end;
    log_info("phdr->p_offset: %lu", phdr->p_offset);
    log_info("phdr->p_filesz: %lu", phdr->p_filesz);
    log_info("filesize: %lu", file_size);
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
    twelf_segment->internal->segment_data = (char *)malloc(phdr->p_filesz > 0 ? phdr->p_filesz : 1); // 1 for preventing zero-size allocation
    if (twelf_segment->internal->segment_data == NULL) {
      log_info("malloc error");
      return_code = ERR_NOMEM;
      goto fail;
    }
    char *segment_data = (char *)((uintptr_t)file_data + phdr->p_offset);
    memcpy(twelf_segment->internal->segment_data, segment_data, phdr->p_filesz);
    twelf_segment->internal->index = i;
    twelf_segment->internal->p_paddr = phdr->p_paddr;
    twelf_segment->internal->p_align = phdr->p_align;
    twelf_segment->internal->p_offset = phdr->p_offset;
    twelf_segment->type = phdr->p_type;
    twelf_segment->vaddr = phdr->p_vaddr;
    twelf_segment->filesize = phdr->p_filesz;
    twelf_segment->memsize = phdr->p_memsz;
    twelf_segment->readable = (phdr->p_flags & PF_R) == PF_R;
    twelf_segment->writeable = (phdr->p_flags & PF_W) == PF_W;
    twelf_segment->executable = (phdr->p_flags & PF_X) == PF_X;
  }

  // create section table with validation
  section_table = (struct LibtwelfSection *)calloc(sizeof(struct LibtwelfSection), ehdr->e_shnum > 0 ? ehdr->e_shnum : 1); // 1 for preventing zero-size allocation
  if (section_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  alloc_section_boundary_table = (Elf64_Off (*)[2])calloc(sizeof(Elf64_Off[2]), ehdr->e_shnum > 0 ? ehdr->e_shnum : 1); // 1 for preventing zero-size allocation
  if (alloc_section_boundary_table == NULL) {
    log_info("calloc error");
    return_code = ERR_NOMEM;
    goto fail;
  }
  Elf64_Shdr *shstrtab_shdr = (Elf64_Shdr *)(((uintptr_t)file_data + ehdr->e_shoff) + ehdr->e_shstrndx * ehdr->e_shentsize);
  for (size_t i = 0; i < ehdr->e_shnum; ++i) {
    Elf64_Shdr *shdr = (Elf64_Shdr *)(((uintptr_t)file_data + ehdr->e_shoff) + i * ehdr->e_shentsize);
    log_info("shdr->sh_entsize: %lu", shdr->sh_entsize);
    // shdr validity check
    Elf64_Off section_end;
    uint64_t section_vaddr_end;
    if (shdr->sh_name >= shstrtab_shdr->sh_size
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
      if (section_partially_overlap_segment(shdr->sh_addr, section_vaddr_end, pt_load_segment_boundary_table[j][0], pt_load_segment_boundary_table[j][1])) {
        log_info("section(index: %lu) paritally overlap or not fully contained within segment(index: %lu)", i, j);
        return_code = ERR_ELF_FORMAT;
        goto fail;
      }
    }
    if (i == SHN_UNDEF && shdr->sh_type != SHT_NULL) {
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
    twelf_section->internal->section_data = (char *)malloc(shdr->sh_size > 0 ? shdr->sh_size : 1); // 1 for preventing zero-size allocation
    if (twelf_section->internal->section_data == NULL) {
      log_info("malloc error");
      return_code = ERR_NOMEM;
      goto fail;
    }
    char *section_data = (char *)((uintptr_t)file_data + shdr->sh_offset);
    memcpy(twelf_section->internal->section_data, section_data, shdr->sh_size);
    twelf_section->internal->index = i;
    twelf_section->internal->sh_addralign = shdr->sh_addralign;
    twelf_section->internal->sh_entsize = shdr->sh_entsize;
    twelf_section->internal->sh_link = shdr->sh_link;
    twelf_section->internal->sh_info = shdr->sh_info;
    twelf_section->internal->sh_offset = shdr->sh_offset; // TODO: remove?
    twelf_section->internal->sh_name = shdr->sh_name;
    twelf_section->name = NULL; // will be filled
    twelf_section->address = shdr->sh_addr;
    twelf_section->size = shdr->sh_size;
    twelf_section->type = shdr->sh_type;
    twelf_section->flags = shdr->sh_flags;
    twelf_section->link = &section_table[shdr->sh_link];

    // update boundary table
    if ((twelf_section->flags & SHF_ALLOC) == SHF_ALLOC) {
      alloc_section_boundary_table[i][0] = twelf_section->address;
      alloc_section_boundary_table[i][1] = section_vaddr_end;
    }
  }
  struct LibtwelfSection *shstrtab_twelf_section = &section_table[ehdr->e_shstrndx];
  for (size_t i = 0; i < ehdr->e_shnum; ++i) {
    struct LibtwelfSection *twelf_section = &section_table[i];
    twelf_section->name = (char *)((uintptr_t)shstrtab_twelf_section->internal->section_data + twelf_section->internal->sh_name);
  }

  // TODO: remove if this validation deducts point (check section overlaps)
  for (size_t i = 0; i < ehdr->e_shnum; ++i) {
    struct LibtwelfSection *twelf_section = &section_table[i];
    if ((twelf_section->flags & SHF_ALLOC) == SHF_ALLOC) {
      for (size_t j = i + 1; j < ehdr->e_shnum; ++j) {
        struct LibtwelfSection *target_twelf_section = &section_table[j];
        if ((target_twelf_section->flags & SHF_ALLOC) == SHF_ALLOC) {
          if (is_overlap(twelf_section->address, twelf_section->address + twelf_section->size, target_twelf_section->address, target_twelf_section->address + target_twelf_section->size)) {
            log_info("SHF_ALLOC sections are overlapping");
            return_code = ERR_ELF_FORMAT;
            goto fail;
          }
        }
      }
    }
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
  twelf_file_internal->file_size = file_size;
  twelf_file_internal->file_data = file_data;
  twelf_file_internal->e_shstrndx = ehdr->e_shstrndx;

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
  free(alloc_section_boundary_table);
  free(pt_load_segment_boundary_table);
  fclose(file);
  log_info("libtwelf_open: Success");
  return return_code;

  fail:
  free(twelf_file);
  free(twelf_file_internal);
  free(file_name);
  free(alloc_section_boundary_table);
  if (section_table != NULL) {
    for (size_t i = 0; i < ehdr->e_shnum; ++i) {
      struct LibtwelfSection *twelf_section = &section_table[i];
      if (twelf_section->internal != NULL) {
        free(twelf_section->internal->section_data);
      }
      free(twelf_section->internal);
    }
  }
  free(section_table);
  free(pt_load_segment_boundary_table);
  if (segment_table != NULL) {
    for (size_t i = 0; i < ehdr->e_phnum; ++i) {
      struct LibtwelfSegment *twelf_segment = &segment_table[i];
      if (twelf_segment->internal != NULL) {
        free(twelf_segment->internal->segment_data);
      }
      free(twelf_segment->internal);
    }
  }
  free(segment_table);
  free(file_data);
  if (file != NULL) {
    fclose(file);
  }
  log_info("libtwelf_open: Fail");
  return return_code;
}


void libtwelf_close(struct LibtwelfFile *twelf)
{
  if (twelf == NULL) {
    return;
  }
  free(twelf->file_name);
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *twelf_section = &twelf->section_table[i];
    free(twelf_section->internal->section_data);
    free(twelf_section->internal);
  }
  free(twelf->section_table);
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
    free(twelf_segment->internal->segment_data);
    free(twelf_segment->internal);
  }
  free(twelf->segment_table);
  free(twelf->internal->file_data);
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
  // *data = (char *)((uintptr_t)twelf->internal->file_data + segment->internal->p_offset);
  *data = segment->internal->segment_data;
  *filesz = segment->filesize;
  *memsz = segment->memsize;
  return SUCCESS;
}

int libtwelf_setSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char *data, size_t filesz, size_t memsz)
{
  // parameter validation
  if (filesz > memsz) {
    return ERR_INVALID_ARG;
  }
  uint64_t altered_segment_start = segment->vaddr;
  uint64_t altered_segment_end;
  if (__builtin_add_overflow(segment->vaddr, memsz, &altered_segment_end)) {
    return ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    uint64_t section_start = section->address;
    uint64_t section_end = section->address + section->size;
    if (section_partially_overlap_segment(section_start, section_end, altered_segment_start, altered_segment_end)) {
      return ERR_INVALID_ARG;
    }
  }
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *target_segment = &twelf->segment_table[i];
    if (target_segment->type != PT_LOAD || target_segment == segment) { // TODO: pointer comparison might not be good identity check; check index?
      continue;
    }
    uint64_t target_segment_start = target_segment->vaddr;
    uint64_t target_segment_end = target_segment->vaddr + target_segment->memsize; // overflow checked by open
    if (is_overlap(altered_segment_start, altered_segment_end, target_segment_start, target_segment_end)) {
      return ERR_INVALID_ARG;
    }
  }

  // write data
  char* new_segment_data = realloc(segment->internal->segment_data, filesz);
  if (new_segment_data == NULL) {
    log_info("realloc error");
    return ERR_NOMEM;
  }
  memcpy(new_segment_data, data, filesz);
  segment->internal->segment_data = new_segment_data;
  segment->filesize = filesz;
  segment->memsize = memsz;

  // write to overlapped segment
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *target_segment = &twelf->segment_table[i];
    if (target_segment == segment) {
      continue;
    }
    uint64_t segment_file_start = segment->vaddr;
    uint64_t segment_file_end = segment->vaddr + segment->filesize;
    uint64_t target_segment_start = target_segment->vaddr;
    uint64_t target_segment_end = target_segment->vaddr + target_segment->filesize; // overflow checked by open
    if (is_overlap(segment_file_start, segment_file_end, target_segment_start, target_segment_end)) {
      uint64_t target_data_offset = segment_file_start > target_segment_start ? segment_file_start - target_segment_start : 0;
      uint64_t data_offset = segment_file_start < target_segment_start ? target_segment_start - segment_file_start : 0;
      uint64_t larger_start = segment_file_start > target_segment_start ? segment_file_start : target_segment_start;
      uint64_t smaller_end = segment_file_end < target_segment_end ? segment_file_end :target_segment_end;
      uint64_t overlapped_size = smaller_end - larger_start;
      char *dest_addr = (char *)((uintptr_t)target_segment->internal->segment_data + target_data_offset);
      char *src_addr = (char *)((uintptr_t)segment->internal->segment_data + data_offset);
      memcpy(dest_addr, src_addr, overlapped_size);
    }
  }

  log_info("setSegmentData: SUCCESS");
  return SUCCESS;
}

int libtwelf_setSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *data, size_t size)
{
  // validation
  uint64_t section_start = section->address;
  uint64_t altered_section_end;
  if (__builtin_add_overflow(section->address, size, &altered_section_end)) {
    return ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *target_section = &twelf->section_table[i]; // TODO: pointer comparison might not be good identity check; check index?
    if (target_section == section) {
      continue;
    }
    uint64_t target_section_start = target_section->address;
    uint64_t target_section_end = target_section->address + target_section->size; // overflow checked by open and setSectionData
    if (is_overlap(section_start, altered_section_end, target_section_start, target_section_end)) {
      return ERR_INVALID_ARG;
    }
  }
  struct LibtwelfSegment *associated_segment = NULL;
  bool segment_found = libtwelf_getAssociatedSegment(twelf, section, &associated_segment) == SUCCESS;
  if (segment_found) {
    uint64_t associated_segment_end = associated_segment->vaddr + associated_segment->filesize; // overflow checked by open and modification functions
    if (altered_section_end > associated_segment_end) {
      return ERR_INVALID_ARG;
    }
  }

  // write
  uint64_t original_size = section->size;
  if (size > original_size) {
    char* new_section_data = realloc(section->internal->section_data, size);
    if (new_section_data == NULL) {
      return ERR_NOMEM;
    }
    section->internal->section_data = new_section_data;
  }
  section->size = size;
  memcpy(section->internal->section_data, data, size);
  if (segment_found) {
    uint64_t offset = section->address - associated_segment->vaddr;
    uint64_t padding_count = original_size > size ? original_size - size : 0;
    char *section_file_start = (char *)((uintptr_t)associated_segment->internal->segment_data + offset);
    log_info("offset: %lu", offset);
    log_info("padding_count: %lu", padding_count);
    memcpy(section_file_start, data, size);
    for (size_t i = 0; i < padding_count; ++i) {
      char *pad_target = (char *)((uintptr_t)section_file_start + size + i);
      *pad_target = 0;
    }
  }
  return SUCCESS;
}

int libtwelf_renameSection(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *name_arg)
{
  int return_value = SUCCESS;
  // need resource management
  char *new_section_data = NULL;
  size_t *name_length_array = NULL;

  // TODO: implementation assumes that shstrtab section is not involved in PT_LOAD segment (else vadliation & write back to segment needed)
  struct LibtwelfSection *shstrtab_twelf_section = &twelf->section_table[twelf->internal->e_shstrndx];
  size_t new_name_length = strlen(name_arg) + 1;

  // reconstruct shstrtab
  name_length_array = (size_t *)calloc(sizeof(size_t), twelf->number_of_sections > 0 ? twelf->number_of_sections : 1); // 1 for preventing zero-size allocation
  if (name_length_array == NULL) {
    log_info("calloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  size_t total_name_size = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *target_section = &twelf->section_table[i];
    if (target_section == section) { // TODO: pointer comparison might not be safe? compare index?
      continue;
    }
    if (target_section->internal->sh_name >= shstrtab_twelf_section->size) { // libtwelf_open checks this, but setSectionData can break this condition
      log_info("section(index: %lu) has invalid sh_name", i);
      return_value = ERR_ELF_FORMAT;
      goto fail;
    }
    uint64_t target_name_limit = shstrtab_twelf_section->size - target_section->internal->sh_name;
    size_t target_section_name_length = strnlen(target_section->name, target_name_limit) + 1; // handle the case when shstrtab does not have terminator on end of string
    if (__builtin_add_overflow(total_name_size, target_section_name_length, &total_name_size)) {
      log_info("new total names size exceeds size_t");
      return_value = ERR_NOMEM;
      goto fail;
    }
    name_length_array[i] = target_section_name_length;
  }
  if (__builtin_add_overflow(total_name_size, new_name_length, &total_name_size)) {
    log_info("new total names size exceeds size_t");
    return_value = ERR_NOMEM;
    goto fail;
  }

  new_section_data = (char *)malloc(total_name_size);
  if (new_section_data == NULL) {
    log_info("malloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  log_info("new_section_data: %p ~ %p", new_section_data, new_section_data + total_name_size);
  size_t current_offset = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *target_section = &twelf->section_table[i];
    if (target_section == section) { // TODO: pointer comparison might not be safe? compare index?
      continue;
    }
    char *current_position = (char *)((uintptr_t)new_section_data + current_offset);
    memcpy(current_position, target_section->name, name_length_array[i]);
    log_info("name write(index: %lu): %p ~ %p", i, current_position, current_position + name_length_array[i]);
    target_section->internal->sh_name = current_offset;
    target_section->name = current_position;
    current_offset += name_length_array[i];
  }
  char *current_position = (char *)((uintptr_t)new_section_data + current_offset);
  memcpy(current_position, name_arg, new_name_length);
  log_info("name write(argument): %p ~ %p", current_position, current_position + new_name_length);
  section->internal->sh_name = current_offset;
  section->name = current_position;
  // current_offset += new_name_length

  // update shstrtab section
  free(shstrtab_twelf_section->internal->section_data);
  shstrtab_twelf_section->internal->section_data = new_section_data;
  shstrtab_twelf_section->size = total_name_size;

  free(name_length_array);
  return return_value;

  fail:
  free(new_section_data);
  free(name_length_array);
  return return_value;
}

int libtwelf_stripSymbols(struct LibtwelfFile *twelf)
{
  // keep in mind to adjust the sh_link values (and the link pointers) for all
  // remaining sections as they may need to be updated
  size_t symtab_count = 0;
  size_t symtab_section_index;
  size_t link_section_index;
  struct LibtwelfSection *symtab_section;
  struct LibtwelfSection *link_section;

  // validation
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    if (section->type == SHT_SYMTAB) {
      if (section->link->type != SHT_STRTAB) {
        log_info(".symtab have invalid link: %u", section->internal->sh_link);
        return ERR_ELF_FORMAT;
      }
      symtab_section_index = i;
      symtab_section = section;
      link_section_index = section->internal->sh_link;
      link_section = section->link;
      symtab_count++;
    }
  }
  if (symtab_count != 1) {
    return ERR_ELF_FORMAT;
  }

  // need resource management
  struct LibtwelfSection *new_section_table = NULL;

  // reconstruct section_table
  new_section_table = (struct LibtwelfSection *)calloc(sizeof(struct LibtwelfSection), twelf->number_of_sections);
  if (new_section_table == NULL) {
    log_info("calloc error");
    return ERR_NOMEM;
  }
  size_t current_index = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    if (i == symtab_section_index || i == link_section_index) {
      continue;
    }
    struct LibtwelfSection *original_section = &twelf->section_table[i];
    struct LibtwelfSection *updated_section = &new_section_table[current_index];
    *updated_section = *original_section;

    Elf64_Word new_sh_link = updated_section->internal->sh_link;
    if (updated_section->internal->sh_link == symtab_section_index || updated_section->internal->sh_link == link_section_index) {
      new_sh_link = 0;
    }
    else {
      if (updated_section->internal->sh_link >= symtab_section_index) {
        new_sh_link--;
      }
      if (updated_section->internal->sh_link >= link_section_index) {
        new_sh_link--;
      }
    }
    updated_section->internal->index = current_index;
    updated_section->internal->sh_link = new_sh_link;
    updated_section->link = &new_section_table[new_sh_link];
    current_index++;
  }
  Elf64_Half new_e_shstrndx = twelf->internal->e_shstrndx;
  if (twelf->internal->e_shstrndx >= symtab_section_index) {
    new_e_shstrndx--;
  }
  if (twelf->internal->e_shstrndx >= link_section_index) {
    new_e_shstrndx--;
  }
  twelf->internal->e_shstrndx = new_e_shstrndx;

  // replace section table
  free(symtab_section->internal->section_data);
  free(symtab_section->internal);
  free(link_section->internal->section_data);
  free(link_section->internal);
  free(twelf->section_table);
  twelf->section_table = new_section_table;
  twelf->number_of_sections = current_index;

  return SUCCESS;
}

int libtwelf_removeAllSections(struct LibtwelfFile *twelf)
{
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    free(section->internal->section_data);
    free(section->internal);
  }
  twelf->number_of_sections = 0;
  return SUCCESS;
}


int libtwelf_addLoadSegment(struct LibtwelfFile *twelf, char *data, size_t len, uint32_t flags, Elf64_Addr vaddr)
{
  int return_value = SUCCESS;

  // validation
  uint64_t new_segment_start = vaddr;
  uint64_t new_segment_end;
  if (__builtin_add_overflow(vaddr, len, &new_segment_end)) {
    log_info("addLoadSegment: vaddr + len overflows");
    return ERR_INVALID_ARG;
  }
  log_info("new_segment range: 0x%lx ~ 0x%lx", new_segment_start, new_segment_end);
  if (flags & ~(PF_R | PF_W | PF_X)) {
    log_info("addLoadSegment: flags involves invalid flag: %u", flags);
    return ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *target_segment = &twelf->segment_table[i];
    uint64_t target_sgement_start = target_segment->vaddr;
    uint64_t target_segment_end = target_segment->vaddr + target_segment->memsize;
    log_info("target_segment range: 0x%lx ~ 0x%lx", target_sgement_start, target_segment_end);
    if (is_overlap(new_segment_start, new_segment_end, target_sgement_start, target_segment_end)) {
      log_info("addLoadSegment: new segment overlaps with another original segment");
      return ERR_INVALID_ARG;
    }
  }

  // need resource management
  struct LibtwelfSegment *new_segment_table = NULL;

  // construct new segment
  struct LibtwelfSegment new_segment = {0,};
  new_segment.internal = (struct LibtwelfSegmentInternal *)calloc(sizeof(struct LibtwelfSegmentInternal), 1);
  if (new_segment.internal == NULL) {
    log_info("calloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  new_segment.internal->segment_data = (char *)malloc(len + 1); // 1 for preventing zero-size allocation
  if (new_segment.internal->segment_data == NULL) {
    log_info("malloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  memcpy(new_segment.internal->segment_data, data, len);
  long page_size = sysconf(_SC_PAGE_SIZE);
  new_segment.internal->p_align = page_size;
  new_segment.internal->p_paddr = vaddr;
  new_segment.internal->p_offset = vaddr % page_size;
  new_segment.vaddr = vaddr;
  new_segment.readable = (flags & PF_R) == PF_R;
  new_segment.writeable = (flags & PF_W) == PF_W;
  new_segment.executable = (flags & PF_X) == PF_X;
  new_segment.filesize = len;
  new_segment.memsize = len;
  new_segment.type = PT_LOAD;

  // reconstruct segment table
  size_t new_segment_count;
  if (__builtin_add_overflow(twelf->number_of_segments, 1, &new_segment_count)) {
    // unlikely case because number_of_segments is originated from Elf64_Half, which is uint16_t
    // even repeating addLoadSegment will not reach overflow, because it would become out of memory before it reach.
    log_info("UNLIKELY CASE: twelf->number_of_sements + 1 overflows");
    return_value = ERR_NOMEM;
    goto fail;
  }
  new_segment_table = (struct LibtwelfSegment *)calloc(sizeof(struct LibtwelfSegment), new_segment_count);
  if (new_segment_table == NULL) {
    log_info("calloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  size_t current_index = 0;
  bool inserted = false;
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *target_segment = &twelf->segment_table[i];
    if (!inserted && target_segment->vaddr > vaddr) {
      new_segment.internal->index = current_index;
      new_segment_table[current_index] = new_segment;
      current_index++;
      inserted = true;
    }
    target_segment->internal->index = current_index;
    new_segment_table[current_index] = *target_segment;
    current_index++;
  }
  if (!inserted) {
    new_segment.internal->index = current_index;
    new_segment_table[current_index] = new_segment;
    current_index++;
    // inserted = true;
  }

  // replace segment table
  free(twelf->segment_table);
  twelf->segment_table = new_segment_table;
  twelf->number_of_segments = new_segment_count;

  return return_value;

  fail:
  if (new_segment.internal != NULL) {
    free(new_segment.internal->segment_data);
  }
  free(new_segment.internal);
  free(new_segment_table);
  return return_value;
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
  if (twelf->number_of_segments > 65535) {
    return ERR_IO;
  }
  int return_value = SUCCESS;
  // need resource management
  FILE *outfile = NULL;
  long *segment_offset_table = NULL;
  Elf64_Phdr *phdr_table = NULL;
  Elf64_Shdr *shdr_table = NULL;
  size_t segment_data_end = sizeof(Elf64_Ehdr);

  outfile = fopen(dest_file, "wb");
  if (outfile == NULL) {
    log_info("fopen error");
    return_value = ERR_IO;
    goto fail;
  }

  // reconstruct phdr table
  size_t phdr_table_end;
  if (__builtin_mul_overflow(sizeof(Elf64_Phdr), twelf->number_of_segments, &phdr_table_end)
   || __builtin_add_overflow(phdr_table_end, sizeof(Elf64_Ehdr), &phdr_table_end)
  ) {
    log_info("elf header + phdr table overflows size_t");
    return_value = ERR_NOMEM;
    goto fail;
  }

  // TODO: remove this code. this is test for test system
  if (fwrite(twelf->internal->file_data, 1, phdr_table_end, outfile) < phdr_table_end) {
    log_info("fwrite error");
    return_value = ERR_IO;
    goto fail;
  }

  long page_size = sysconf(_SC_PAGE_SIZE);
  log_info("page_size: 0x%lx", page_size);
  segment_offset_table = (long *)calloc(sizeof(long), twelf->number_of_segments > 0 ? twelf->number_of_segments : 1); // 1 for preventing zero-size allocation
  if (segment_offset_table == NULL) {
    log_info("calloc error");
    return_value = ERR_NOMEM;
    goto fail;
  }
  if (twelf->number_of_segments > 0) {
    for (size_t i = 0; i < twelf->number_of_segments; ++i) {
      struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
      // segment_offset_table[i] = twelf_segment->internal->p_offset;
      segment_offset_table[i] = twelf_segment->vaddr % page_size;
    }
    for (size_t i = 0; i < twelf->number_of_segments; ++i) {
      if ((size_t)segment_offset_table[i] < phdr_table_end) {
        size_t phdr_table_page_count = phdr_table_end / page_size;
        phdr_table_page_count += phdr_table_end % page_size > 0 ? 1 : 0;
        size_t offset_adjust;
        if (__builtin_mul_overflow(page_size, phdr_table_page_count, &offset_adjust)) {
          log_info("phdr table spans all pages");
          return_value = ERR_NOMEM;
          goto fail;
        }
        log_info("segment(index: %lu) overlaps with phdr table", i);
        for (size_t j = 0; j < twelf->number_of_segments; ++j) {
          if (__builtin_add_overflow(segment_offset_table[j], offset_adjust, &segment_offset_table[j])) {
            log_info("segment offset overflows long after reallocation (by phdr table)");
            return_value = ERR_IO;
            goto fail;
          }
        }
        break;
      }
    }
    for (size_t i = 0; i < twelf->number_of_segments; ++i) {
      struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
      for (size_t j = i + 1; j < twelf->number_of_segments; ++j) {
        struct LibtwelfSegment *compare_target_twelf_segment = &twelf->segment_table[j];
        if (is_overlap(twelf_segment->vaddr, twelf_segment->vaddr + twelf_segment->memsize, compare_target_twelf_segment->vaddr, compare_target_twelf_segment->vaddr + compare_target_twelf_segment->memsize)) {
            long original_offset = segment_offset_table[j];
            long diff;
            if (__builtin_sub_overflow(compare_target_twelf_segment->vaddr, twelf_segment->vaddr, &diff)
             || __builtin_add_overflow(segment_offset_table[i], diff, &segment_offset_table[j])
            ) {
              log_info("segment offset overflows long after reallocation (by vaddr overlap)");
              return_value = ERR_IO;
              goto fail;
            }
            log_info("overlapping segment relocated: 0x%lx -> 0x%lx", original_offset, segment_offset_table[j]);
            continue;
        }
        while (is_overlap(segment_offset_table[i], segment_offset_table[i] + twelf_segment->filesize, segment_offset_table[j], segment_offset_table[j] + compare_target_twelf_segment->filesize)) {
          log_info("PT_LOAD segments on different virtual addresses overlap on file (%lu <-> %lu) adjust later segment offset by adding PAGE_SIZE", i, j);
          for (size_t k = j; k < twelf->number_of_segments; ++k) {
            if (__builtin_add_overflow(segment_offset_table[k], page_size, &segment_offset_table[k])) {
              log_info("segment offset overflows long after reallocation (by file overlap)");
              return_value = ERR_IO;
              goto fail;
            }
          }
        }
      }
    }
    phdr_table = (Elf64_Phdr *)calloc(sizeof(Elf64_Phdr), twelf->number_of_segments > 0 ? twelf->number_of_segments : 1); // 1 for preventing zero-size allocation
    if (phdr_table == NULL) {
      log_info("calloc error");
      return_value = ERR_NOMEM;
      goto fail;
    }
    for (size_t i = 0; i < twelf->number_of_segments; ++i) {
      struct LibtwelfSegment *twelf_segment = &twelf->segment_table[i];
      size_t segment_end_on_file;
      if (__builtin_add_overflow(segment_offset_table[i], twelf_segment->filesize, &segment_end_on_file)) {
        log_info("segment end overflows long after reallocation");
        return_value = ERR_IO;
        goto fail;
      }
      if (segment_end_on_file > segment_data_end) {
        segment_data_end = segment_end_on_file;
      }

      Elf64_Phdr *segment = &phdr_table[i];
      segment->p_type = twelf_segment->type;
      segment->p_flags = 0;
      if (twelf_segment->executable) {
        segment->p_flags |= PF_X;
      }
      if (twelf_segment->writeable) {
        segment->p_flags |= PF_W;
      }
      if (twelf_segment->readable) {
        segment->p_flags |= PF_R;
      }
      segment->p_offset = segment_offset_table[i];
      segment->p_vaddr = twelf_segment->vaddr;
      segment->p_paddr = twelf_segment->internal->p_paddr;
      segment->p_filesz = twelf_segment->filesize;
      segment->p_memsz = twelf_segment->memsize;
      segment->p_align = twelf_segment->internal->p_align;
      if (fseek(outfile, segment_offset_table[i], SEEK_SET)) {
        log_info("fseek error");
        return_value = ERR_IO;
        goto fail;
      }
      if (fwrite(twelf_segment->internal->segment_data, 1, twelf_segment->filesize, outfile) < twelf_segment->filesize) {
        log_info("fwrite error");
        return_value = ERR_IO;
        goto fail;
      }
    }
  }
  log_info("wrote segment data");

  // reconstruct shdr table and also write data if no associated segment exists
  long shdr_table_position = 0;
  if (twelf->number_of_sections > 0) {
    shdr_table = (Elf64_Shdr *)calloc(sizeof(Elf64_Shdr), twelf->number_of_sections > 0 ? twelf->number_of_sections : 1); // 1 for preventing zero-size allocation
    if (shdr_table == NULL) {
      log_info("calloc error");
      return_value = ERR_NOMEM;
      goto fail;
    }
    // unusual case: section with SHF_ALLOC does not have associated segment
    size_t non_alloc_section_data_start = segment_data_end;
    for (size_t i = 0; i < twelf->number_of_sections; ++i) {
      struct LibtwelfSection *twelf_section = &twelf->section_table[i];
      struct LibtwelfSegment *associated_twelf_segment;
      if ((twelf_section->flags & SHF_ALLOC) == SHF_ALLOC
       && libtwelf_getAssociatedSegment(twelf, twelf_section, &associated_twelf_segment) == ERR_NOT_FOUND
       && twelf_section->type != SHT_NULL
      ) {
        log_info("unusual case: section(index: %lu) with SHF_ALLOC without associated segment", i);
        // TODO: non-associated section & non-PT_LOAD segment overlap -> adjust offset to overlap in file, otherwise non-PT_LOAD overlapping data are written twice.
        // TODO: implemented in dumb way --> writing on the next page of segment data / can check & write on the same page if not overlapped
        // TODO: if offset should also be aligned by sh_addralign, compare page_size <> sh_addralign and larger one for alignment
        long section_data_offset;
        size_t section_data_end;
        if (__builtin_add_overflow(non_alloc_section_data_start, (page_size - (non_alloc_section_data_start % page_size)) % page_size, &section_data_offset)
         || __builtin_add_overflow(section_data_offset, twelf_section->internal->sh_offset, &section_data_offset)
         || __builtin_add_overflow(section_data_offset, twelf_section->size, &section_data_end)
        ) {
          log_info("reallocated section offset overflows uint64_t");
          return_value = ERR_IO;
          goto fail;
        }
        non_alloc_section_data_start = section_data_end > non_alloc_section_data_start ? section_data_end : non_alloc_section_data_start;
        twelf_section->internal->sh_offset = section_data_offset;
        if (fseek(outfile, section_data_offset, SEEK_SET)) {
          log_info("fseek fail");
          return_value = ERR_IO;
          goto fail;
        }
        if (fwrite(twelf_section->internal->section_data, 1, twelf_section->size, outfile) < twelf_section->size) {
          log_info("fwrite error");
          return_value = ERR_IO;
          goto fail;
        }
      }
    }
    if (fseek(outfile, non_alloc_section_data_start, SEEK_SET)) {
      log_info("fseek fail");
      return_value = ERR_IO;
      goto fail;
    }
    for (size_t i = 0; i < twelf->number_of_sections; ++i) {
      struct LibtwelfSection *twelf_section = &twelf->section_table[i];
      struct LibtwelfSegment *associated_twelf_segment;
      Elf64_Off section_offset = twelf_section->internal->sh_offset;
      log_info("processing section(index: %lu)", i);

      bool associated_segment_found = libtwelf_getAssociatedSegment(twelf, twelf_section, &associated_twelf_segment) == SUCCESS;
      if ((twelf_section->flags & SHF_ALLOC) != SHF_ALLOC
       && !associated_segment_found
       && twelf_section->type != SHT_NULL
      ) {
        long cur_position = ftell(outfile);
        if (cur_position == -1) {
          log_info("ftell fail");
          return_value = ERR_IO;
          goto fail;
        }
        if (twelf_section->internal->sh_addralign > 0 ) {
          long alignment = (twelf_section->internal->sh_addralign - (cur_position % twelf_section->internal->sh_addralign)) % twelf_section->internal->sh_addralign;
          if (__builtin_add_overflow(cur_position, alignment, &cur_position)) {
            log_info("section_offset exceeds long after alignment");
            return_value = ERR_IO;
            goto fail;
          }
          if (fseek(outfile, cur_position, SEEK_SET)) {
            log_info("fseek error");
            return_value = ERR_IO;
            goto fail;
          }
        }
        section_offset = cur_position;
        log_info("non-associated section(index: %lu) offset recalculated: %lu -> %lu", i, twelf_section->internal->sh_offset, section_offset);
        if (twelf_section->type != SHT_NOBITS) {
          if (fwrite(twelf_section->internal->section_data, 1, twelf_section->size, outfile) < twelf_section->size) {
            log_info("fwrite error");
            return_value = ERR_IO;
            goto fail;
          }
        }
      } else {
        log_info("section(index: %lu) uses original offset", i);
      }
      if (associated_segment_found) {
        long new_section_offset;
        if (__builtin_add_overflow(segment_offset_table[associated_twelf_segment->internal->index], twelf_section->address - associated_twelf_segment->vaddr,  &new_section_offset)) {
          log_info("reallocation of section inside reallocated segment offset overflows");
          return_value = ERR_IO;
          goto fail;
        }
        section_offset = new_section_offset;
        log_info("associated section(index: %lu) offset recalculated: %lu -> %ld", i, twelf_section->internal->sh_offset, section_offset);
      }
      Elf64_Shdr *section = &shdr_table[i];
      section->sh_name = twelf_section->internal->sh_name;
      section->sh_type = twelf_section->type;
      section->sh_flags = twelf_section->flags;
      section->sh_addr = twelf_section->address;
      section->sh_offset = section_offset;
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
    shdr_table_position = ftell(outfile);
    if (shdr_table_position == -1) {
      log_info("ftell fail");
      return_value = ERR_IO;
      goto fail;
    }
    log_info("shdr_table_position: %ld", shdr_table_position);
    if (__builtin_add_overflow(shdr_table_position, (8 - (shdr_table_position % 8)) % 8, &shdr_table_position)) {
      log_info("shdr_table_position overflows after alignment");
      return_value = ERR_IO;
      goto fail;
    }
    log_info("shdr_table_position (aligned): %ld", shdr_table_position);
    if (fseek(outfile, shdr_table_position, SEEK_SET)) {
      log_info("fseek fail");
      return_value = ERR_IO;
      goto fail;
    }
    if (fwrite(shdr_table, sizeof(Elf64_Shdr), twelf->number_of_sections, outfile) < twelf->number_of_sections) {
      log_info("fwrite error");
      return_value = ERR_IO;
      goto fail;
    }
  }
  // write phdr table
  long phdr_table_position = sizeof(Elf64_Ehdr);
  if (twelf->number_of_segments > 0) {
    // phdr_table_position = ftell(outfile);
    // if (phdr_table_position == -1) {
    //   log_info("ftell fail");
    //   return_value = ERR_IO;
    //   goto fail;
    // }
    log_info("phdr_table_position: %ld", phdr_table_position);
    if (fseek(outfile, phdr_table_position, SEEK_SET)) {
      log_info("fseek fail");
      return_value = ERR_IO;
      goto fail;
    }
    if (fwrite(phdr_table, sizeof(Elf64_Phdr), twelf->number_of_segments, outfile) < twelf->number_of_segments) {
      log_info("fwrite error");
      return_value = ERR_IO;
      goto fail;
    }
  }

  // reconstruct and write ehdr
  Elf64_Ehdr *ehdr = (Elf64_Ehdr *)twelf->internal->file_data;
  log_info("ehdr = %p", ehdr);
  ehdr->e_shoff = shdr_table_position;
  ehdr->e_phoff = phdr_table_position;
  ehdr->e_shnum = twelf->number_of_sections;
  ehdr->e_phnum = twelf->number_of_segments;
  ehdr->e_shstrndx = twelf->internal->e_shstrndx;
  log_info("reconstructed ehdr->e_shoff: %lu", ehdr->e_shoff);
  log_info("reconstructed ehdr->e_phoff: %lu", ehdr->e_phoff);
  if (fseek(outfile, 0, SEEK_SET)) {
    log_info("fseek fail");
    return_value = ERR_IO;
    goto fail;
  }
  if (fwrite(ehdr, 1, sizeof(Elf64_Ehdr), outfile) < sizeof(Elf64_Ehdr)) {
    log_info("fwrite error");
    return_value = ERR_IO;
    goto fail;
  }

  // clean resources
  free(shdr_table);
  free(phdr_table);
  free(segment_offset_table);
  fclose(outfile);
  return return_value;

  fail:
  free(shdr_table);
  free(phdr_table);
  free(segment_offset_table);
  if (outfile != NULL) {
    fclose(outfile);
  }
  return return_value;
}

int libtwelf_getAssociatedSegment(struct LibtwelfFile *twelf, struct LibtwelfSection *section, struct LibtwelfSegment **result)
{
  uint64_t section_start = section->address;
  uint64_t section_end = section->address + section->size; // overflow checked by open
  for (size_t i = 0; i < twelf->number_of_segments; ++i) {
    struct LibtwelfSegment *segment = &twelf->segment_table[i];
    if (segment->type == PT_LOAD && segment->vaddr <= section_start && section_end <= segment->vaddr + segment->memsize) { // overflow checked by open
      *result = segment;
      return SUCCESS;
    }
  }
  return ERR_NOT_FOUND;
}

int libtwelf_resolveSymbol(struct LibtwelfFile *twelf, const char *name, Elf64_Addr *st_value)
{
  bool symtab_found = false;
  const char *symtab_section_data = NULL;
  const char *strtab_section_data = NULL;
  size_t symtab_section_size = 0;
  size_t strtab_section_size = 0;
  Elf64_Xword entsize = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    if (section->type == SHT_SYMTAB) {
      entsize = section->internal->sh_entsize;
      symtab_section_size = section->size;
      symtab_section_data =  section->internal->section_data;
      // remove or retain after test --> No effect on score
      if (section->link->type != SHT_STRTAB) {
        return ERR_ELF_FORMAT;
      }
      strtab_section_size = section->link->size;
      strtab_section_data = section->link->internal->section_data;
      symtab_found = true;
      break;
    }
  }
  if (!symtab_found) {
    return ERR_ELF_FORMAT;
  }
  log_info("symtab_section_size: %lu, entsize: %lu, sizeof(Elf64_Sym): %lu", symtab_section_size, entsize, sizeof(Elf64_Sym));
  size_t symbol_size = entsize >= sizeof(Elf64_Sym) ? entsize : sizeof(Elf64_Sym);
  size_t symbol_count = symtab_section_size / symbol_size;
  // TODO: determine retain or remove after test
  if (symtab_section_size % symbol_size != 0) {
    return ERR_ELF_FORMAT;
  }
  for (size_t i = 0; i < symbol_count; ++i) {
    Elf64_Sym *symbol = (Elf64_Sym *)((uintptr_t)symtab_section_data + i * symbol_size);
    // TODO: when to check st_name validity?: resolveSymbol or open
    if (symbol->st_name >= strtab_section_size) {
      return ERR_ELF_FORMAT;
    }
    if (strcmp(name, strtab_section_data + symbol->st_name) == 0) {
      *st_value = symbol->st_value;
      log_info("symbol->st_shndx: %u", symbol->st_shndx);
      return SUCCESS;
    }
  }
  return ERR_NOT_FOUND;
}

int libtwelf_addSymbol(struct LibtwelfFile *twelf, struct LibtwelfSection* section, const char *name, unsigned char type, Elf64_Addr st_value)
{

  // TODO: implementation assumes that shstrtab section is not involved in PT_LOAD segment (else vadliation & write back to segment needed)
  // validation
  if (type != STT_FUNC && type != STT_OBJECT) {
    // this validation is not specified in libtwelf.h, but removing this results in point deduction
    return ERR_INVALID_ARG;
  }
  bool symtab_found = false;
  struct LibtwelfSection *symtab_section;
  struct LibtwelfSection *strtab_section;
  Elf64_Xword entsize = 0;
  for (size_t i = 0; i < twelf->number_of_sections; ++i) {
    struct LibtwelfSection *section = &twelf->section_table[i];
    if (section->type == SHT_SYMTAB) {
      entsize = section->internal->sh_entsize;
      symtab_section = section;
      if (section->link->type != SHT_STRTAB) {
        return ERR_ELF_FORMAT;
      }
      strtab_section = section->link;
      symtab_found = true;
      break;
    }
  }
  if (!symtab_found) {
    return ERR_ELF_FORMAT;
  }

  // reconstruct strtab section data
  size_t new_strtab_section_size;
  size_t new_name_size = strlen(name) + 1;
  if (__builtin_add_overflow(strtab_section->size, new_name_size, &new_strtab_section_size)) {
    log_info("strtab section new size overflows size_t");
    return ERR_NOMEM;
  }
  char *new_strtab_section_data = (char *)malloc(new_strtab_section_size);
  if (new_strtab_section_data == NULL) {
    log_info("malloc error");
    return ERR_NOMEM;
  }
  memcpy(new_strtab_section_data, strtab_section->internal->section_data, strtab_section->size);
  strncpy(new_strtab_section_data + strtab_section->size, name, new_name_size);

  // reconstruct symtab section data
  log_info("symtab_section_size: %lu, entsize: %lu, sizeof(Elf64_Sym): %lu", symtab_section->size, entsize, sizeof(Elf64_Sym));
  size_t symbol_size = entsize >= sizeof(Elf64_Sym) ? entsize : sizeof(Elf64_Sym);
  size_t symbol_count = symtab_section->size / symbol_size;
  size_t new_symtab_section_size;
  if (__builtin_mul_overflow(symbol_size, symbol_count + 1, &new_symtab_section_size)) {
    log_info("strtab section new size overflows size_t");
    free(new_strtab_section_data);
    return ERR_NOMEM;
  }
  char *new_symtab_section_data = (char *)calloc(symbol_size, symbol_count + 1);
  if (new_symtab_section_data == NULL) {
    log_info("calloc error");
    free(new_strtab_section_data);
    return ERR_NOMEM;
  }
  memcpy(new_symtab_section_data, symtab_section->internal->section_data, symtab_section->size);
  Elf64_Sym *new_symbol = (Elf64_Sym *)((uintptr_t)new_symtab_section_data + symbol_size * symbol_count);
  new_symbol->st_name = strtab_section->size;
  new_symbol->st_info = ELF32_ST_INFO(STB_GLOBAL, type);
  new_symbol->st_other = STV_DEFAULT;
  new_symbol->st_shndx = section->internal->index;
  new_symbol->st_value = st_value;
  new_symbol->st_size = 0;

  // update sections
  strtab_section->size = new_strtab_section_size;
  free(strtab_section->internal->section_data);
  strtab_section->internal->section_data = new_strtab_section_data;
  symtab_section->size = new_symtab_section_size;
  free(symtab_section->internal->section_data);
  symtab_section->internal->section_data = new_symtab_section_data;

  return SUCCESS;
}
