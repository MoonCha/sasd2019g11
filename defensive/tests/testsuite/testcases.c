#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <twelf.h>
#include <malloc.h>

#include "libtwelf.h"
#include "alloc_wrapper.h"

START_TEST (libtwelf_open_fail)
{
  struct LibtwelfFile *twelf = NULL;
  set_io_failcounter(1);
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, ERR_IO);

  set_alloc_failcounter(1);
  ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, ERR_NOMEM);

  for (size_t i = 1; i < 18; ++i) {
    set_alloc_failcounter(i);
    ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
    ck_assert_int_eq(ret, ERR_NOMEM);
  }

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_invalid_elf_header)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/invalid_elf_header1.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header2.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header3.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header4.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header5.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header6.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header7.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header8.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_elf_header9.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);
}
END_TEST

START_TEST (libtwelf_open_invalid_program_header)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/invalid_program_header1.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header2.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header3.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);
  
  ret = libtwelf_open("../test_elfs/invalid_program_header4.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header5.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header6.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header7.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header8.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_program_header9.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);
}
END_TEST

START_TEST (libtwelf_open_invalid_section_header)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/invalid_section_header1.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header2.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header3.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);
  
  ret = libtwelf_open("../test_elfs/invalid_section_header4.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header5.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header6.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header7.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ret = libtwelf_open("../test_elfs/invalid_section_header8.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  // section <> segment partial overlap check
  ret = libtwelf_open("../test_elfs/invalid_section_header9.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  // section contains PT_LOAD segment (--> section is not fully contained within a PT_LOAD segment)
  ret = libtwelf_open("../test_elfs/invalid_section_header10.elf", &twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);
}
END_TEST

START_TEST (libtwelf_open_empty_elf)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 0);
  ck_assert_int_eq(twelf->number_of_sections, 0);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_filename)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert_int_eq(ret, 0);
  ck_assert_str_eq("../test_elfs/empty.elf", twelf->file_name);
  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_segments_one)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/infiniteloop_mini.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(twelf->number_of_segments, 1);
  ck_assert_int_eq(twelf->segment_table[0].type, PT_LOAD);
  ck_assert_int_eq(twelf->segment_table[0].vaddr, 0x0000000000010000);
  ck_assert_int_eq(twelf->segment_table[0].filesize, 0x000000000000007a);
  ck_assert_int_eq(twelf->segment_table[0].memsize, 0x0000000000001000);
  ck_assert_int_eq(twelf->segment_table[0].readable, true);
  ck_assert_int_eq(twelf->segment_table[0].writeable, true);
  ck_assert_int_eq(twelf->segment_table[0].executable, true);
  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_section_name)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(twelf->number_of_sections, 3);
  ck_assert_str_eq(twelf->section_table[0].name, "");
  ck_assert_str_eq(twelf->section_table[1].name, ".text");
  ck_assert_str_eq(twelf->section_table[2].name, ".shstrtab");
  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_io)
{
  struct LibtwelfFile *twelf;
  set_io_failcounter(1);
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert_int_eq(ret, ERR_IO);
}
END_TEST

START_TEST (libtwelf_getAssociatedSegment_basic)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  struct LibtwelfSegment *segment = NULL;

  ret = libtwelf_getAssociatedSegment(twelf, &twelf->section_table[0], &segment);
  ck_assert_int_eq(ret, ERR_NOT_FOUND);

  ret = libtwelf_getAssociatedSegment(twelf, &twelf->section_table[1], &segment);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(segment == &twelf->segment_table[0]);

  ret = libtwelf_getAssociatedSegment(twelf, &twelf->section_table[2], &segment);
  ck_assert_int_eq(ret, ERR_NOT_FOUND);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_fail)
{
  struct LibtwelfFile *twelf = NULL;

  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);

  set_io_failcounter(1);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_fail_output.elf");
  ck_assert_int_eq(ret, ERR_IO);

  for (size_t i = 1; i < 4; ++i) {
    printf("current i = %lu\n", i);
    set_alloc_failcounter(i);
    ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_fail_output.elf");
    ck_assert_int_eq(ret, ERR_NOMEM);
  }

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_basic)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_basic_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_basic_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_simple)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_simple_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_simple_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_symtab)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_symtab_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_symtab_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_infiniteloop_mini)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/infiniteloop_mini.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_infiniteloop_mini_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_infiniteloop_mini_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_gcc1)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/gcc1.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_gcc1_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_gcc1_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_write_orphaned_alloc_section)
{
  struct LibtwelfFile *twelf = NULL;
  char data[100];
  int ret = libtwelf_open("../test_elfs/orphaned_alloc_section.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(twelf != NULL);
  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_write_orphaned_alloc_section_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  FILE *file = fopen("../test_elfs/libtwelf_write_orphaned_alloc_section_output.elf", "r");
  ck_assert_int_ne(0, fread(data, 16, 1, file));
  fclose(file);
  ck_assert(0 == memcmp(data, "\x7f\x45\x4c\x46\x02\x01\x01\0\0\0\0\0\0\0\0\0", 16));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_getSectionData_basic)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  const char *data;
  size_t len;

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 8);
  ck_assert(0 == memcmp(data, "\x31\xc0\xff\xc0\x89\xc3\xcd\x80", 8));

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[2], &data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 17);
  ck_assert(0 == memcmp(data, "\0.text\0.shstrtab\0", 17));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_getSegmentData_basic)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  const char *data = NULL;
  size_t filesz = 0;
  size_t memsz = 0;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(data, "\x31\xc0\xff\xc0\x89\xc3\xcd\x80", 8));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  ck_assert(0 == memcmp(data, "\x01\x02\x03\x04\x05\x06\x07", 7));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_renameSection_fail)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ck_assert_str_eq(twelf->section_table[0].name, "");
  ck_assert_str_eq(twelf->section_table[1].name, ".text");
  ck_assert_str_eq(twelf->section_table[2].name, ".shstrtab");

  set_alloc_failcounter(1);
  ret = libtwelf_renameSection(twelf, &twelf->section_table[1], ".title");
  ck_assert_int_eq(ret, ERR_NOMEM);
  ck_assert_str_eq(twelf->section_table[1].name, ".text");

  set_alloc_failcounter(2);
  ret = libtwelf_renameSection(twelf, &twelf->section_table[1], ".title");
  ck_assert_int_eq(ret, ERR_NOMEM);
  ck_assert_str_eq(twelf->section_table[1].name, ".text");

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[2], "\0", 1);
  ret = libtwelf_renameSection(twelf, &twelf->section_table[1], ".title");
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_renameSection_basic)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ck_assert_str_eq(twelf->section_table[0].name, "");
  ck_assert_str_eq(twelf->section_table[1].name, ".text");
  ck_assert_str_eq(twelf->section_table[2].name, ".shstrtab");

  ret = libtwelf_renameSection(twelf, &twelf->section_table[1], ".title");
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_str_eq(twelf->section_table[1].name, ".title");

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_renameSection_basic_with_write)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ck_assert_str_eq(twelf->section_table[0].name, "");
  ck_assert_str_eq(twelf->section_table[1].name, ".text");
  ck_assert_str_eq(twelf->section_table[2].name, ".shstrtab");

  ret = libtwelf_renameSection(twelf, &twelf->section_table[1], ".title");
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_str_eq(twelf->section_table[1].name, ".title");

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_renameSection_basic_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_renameSection_basic_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ck_assert_str_eq(twelf->section_table[0].name, "");
  ck_assert_str_eq(twelf->section_table[1].name, ".title");
  ck_assert_str_eq(twelf->section_table[2].name, ".shstrtab");

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSegmentData_fail)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  const char *orig_data;
  size_t orig_filesz;
  size_t orig_memsz;

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &orig_data, &orig_filesz, &orig_memsz);
  ck_assert_int_eq(ret, SUCCESS);

  set_alloc_failcounter(1);
  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[1], data, 3, 10);
  ck_assert_int_eq(ret, ERR_NOMEM);

  const char *out_data;
  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, orig_filesz);
  ck_assert_int_eq(memsz, orig_memsz);
  ck_assert(0 == memcmp(out_data, orig_data, orig_filesz));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSegmentData_invalid_args)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  const char *out_data;
  size_t filesz;
  size_t memsz;
  char *orig_segment0_data = (char *)malloc(twelf->segment_table[0].filesize);
  ck_assert(orig_segment0_data != NULL);
  char *orig_segment1_data = (char *)malloc(twelf->segment_table[1].filesize);
  ck_assert(orig_segment0_data != NULL);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  memcpy(orig_segment0_data, out_data, filesz);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  memcpy(orig_segment1_data, out_data, filesz);

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[0], data, 9, 9);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[0], data, 8, 6);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[1], data, 0xffffffffffffffff, 0xffffffffffffffff);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_removeAllSections(twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[1], data, 0xffffffffffffffff, 0xffffffffffffffff);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(out_data, orig_segment0_data, 8));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  ck_assert(0 == memcmp(out_data, orig_segment1_data, 7));

  libtwelf_close(twelf);

  free(orig_segment0_data);
  free(orig_segment1_data);
}
END_TEST

START_TEST (libtwelf_setSegmentData_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[1], data, 3, 10);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 3);
  ck_assert_int_eq(memsz, 10);
  ck_assert(0 == memcmp(out_data, data, 3));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSegmentData_basic_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[1], data, 3, 10);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 3);
  ck_assert_int_eq(memsz, 10);
  ck_assert(0 == memcmp(out_data, data, 3));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_setSegmentData_basic_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_setSegmentData_basic_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 3);
  ck_assert_int_eq(memsz, 10);
  ck_assert(0 == memcmp(out_data, data, 3));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSegmentData_overlapped_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/overlapped.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  ret = libtwelf_setSegmentData(twelf, &twelf->segment_table[0], data, 3, 10);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 3);
  ck_assert_int_eq(memsz, 10);
  ck_assert(0 == memcmp(out_data, data, 3));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  ck_assert(0 == memcmp(out_data, data, 3));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_setSegmentData_overlapped_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_setSegmentData_overlapped_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 3);
  ck_assert_int_eq(memsz, 10);
  ck_assert(0 == memcmp(out_data, data, 3));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  ck_assert(0 == memcmp(out_data, data, 3));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSectionData_fail)
{
  struct LibtwelfFile *twelf;
  const char *out_data;
  size_t len;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[18] = {0x00, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x00};

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[2], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 17);
  char orig_data[17];
  memcpy(orig_data, out_data, len);

  set_alloc_failcounter(1);
  ret = libtwelf_setSectionData(twelf, &twelf->section_table[2], data, 18);
  ck_assert_int_eq(ret, ERR_NOMEM);

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[2], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 17);
  ck_assert(0 == memcmp(out_data, orig_data, len));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSectionData_invalid_args)
{
  struct LibtwelfFile *twelf;
  const char *out_data;
  size_t len;
  int ret = libtwelf_open("../test_elfs/simple2.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 4);

  char data[9] = {0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 8);
  char *section_1_orig_data = (char *)malloc(len);
  ck_assert(section_1_orig_data != NULL);
  memcpy(section_1_orig_data, out_data, len);

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[3], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 7);
  char *section_3_orig_data = (char *)malloc(len);
  ck_assert(section_3_orig_data != NULL);
  memcpy(section_3_orig_data, out_data, len);

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[1], data, 0xffffffffffffffff);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[1], data, 9);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[3], data, 9);
  ck_assert_int_eq(ret, ERR_INVALID_ARG);

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 8);
  ck_assert(0 == memcmp(out_data, section_1_orig_data, len));

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[3], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 7);
  ck_assert(0 == memcmp(out_data, section_3_orig_data, len));

  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(out_data, section_1_orig_data, 8));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 7);
  ck_assert_int_eq(memsz, 7);
  ck_assert(0 == memcmp(out_data, section_3_orig_data, 7));

  libtwelf_close(twelf);
  free(section_1_orig_data);
  free(section_3_orig_data);
}
END_TEST

START_TEST (libtwelf_setSectionData_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[1], data, 3);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t len;

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 3);
  ck_assert(0 == memcmp(out_data, data, 3));

  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(out_data, "\x07\x06\x05\x00\x00\x00\x00\x00", 8));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSectionData_basic_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[3] = {0x07, 0x06, 0x05};

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[1], data, 3);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t len;

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 3);
  ck_assert(0 == memcmp(out_data, data, 3));

  size_t filesz;
  size_t memsz;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(out_data, "\x07\x06\x05\x00\x00\x00\x00\x00", 8));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_setSectionData_basic_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_setSectionData_basic_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[1], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 3);
  ck_assert(0 == memcmp(out_data, data, 3));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &out_data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, 8);
  ck_assert_int_eq(memsz, 8);
  ck_assert(0 == memcmp(out_data, "\x07\x06\x05\x00\x00\x00\x00\x00", 8));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_setSectionData_non_associated_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char data[18] = {0x00, 0x11, 0x10, 0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x00};

  ret = libtwelf_setSectionData(twelf, &twelf->section_table[2], data, 18);
  ck_assert_int_eq(ret, SUCCESS);

  const char *out_data;
  size_t len;

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[2], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 18);
  ck_assert(0 == memcmp(out_data, data, 18));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_setSectionData_non_associated_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_setSectionData_non_associated_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ret = libtwelf_getSectionData(twelf, &twelf->section_table[2], &out_data, &len);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(len, 18);
  ck_assert(0 == memcmp(out_data, data, 18));

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_stripSymbols_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  ret = libtwelf_stripSymbols(twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_stripSymbols_basic_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  ret = libtwelf_stripSymbols(twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_stripSymbols_basic_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_stripSymbols_basic_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_stripSymbols_without_symtab)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_stripSymbols(twelf);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_removeAllSections_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  ret = libtwelf_removeAllSections(twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 0);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_removeAllSections_simple_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_removeAllSections(twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 0);

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_removeAllSections_simple_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_removeAllSections_simple_with_write_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 0);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addLoadSegment_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char segment[0x1234];
  memset(segment, 0x90, sizeof(segment));
  ret = libtwelf_addLoadSegment(twelf, segment, sizeof(segment), PF_W | PF_R | PF_X, 0xdeadbeef);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 3);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  const char *data = NULL;
  size_t filesz = 0;
  size_t memsz = 0;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[2], &data, &filesz, &memsz) ;
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, sizeof(segment));
  ck_assert_int_eq(memsz, sizeof(segment));
  ck_assert(0 == memcmp(data, segment, sizeof(segment)));

  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addLoadSegment_basic_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  char segment[0x1234];
  memset(segment, 0x90, sizeof(segment));
  ret = libtwelf_addLoadSegment(twelf, segment, sizeof(segment), PF_W | PF_R | PF_X, 0xdeadbeef);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 3);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  const char *data = NULL;
  size_t filesz = 0;
  size_t memsz = 0;
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[2], &data, &filesz, &memsz) ;
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, sizeof(segment));
  ck_assert_int_eq(memsz, sizeof(segment));
  ck_assert(0 == memcmp(data, segment, sizeof(segment)));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_addLoadSegment_basic_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_addLoadSegment_basic_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 3);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[2], &data, &filesz, &memsz) ;
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, sizeof(segment));
  ck_assert_int_eq(memsz, sizeof(segment));
  ck_assert(0 == memcmp(data, segment, sizeof(segment)));

  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addLoadSegment_offset_overlap)
{
  struct LibtwelfFile *twelf;
  const char *data = NULL;
  size_t filesz = 0;
  size_t memsz = 0;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  char *segment_0_data = (char *)malloc(filesz);
  ck_assert(segment_0_data != NULL);
  memcpy(segment_0_data, data, filesz);
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  char *segment_1_data = (char *)malloc(filesz);
  ck_assert(segment_1_data != NULL);
  memcpy(segment_1_data, data, filesz);

  char segment[0x1234];
  memset(segment, 0x90, sizeof(segment));
  ret = libtwelf_addLoadSegment(twelf, segment, sizeof(segment), PF_W | PF_R | PF_X, 0x00000000080480b0 + 0x1000);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 3);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(0 == memcmp(data, segment_0_data, filesz));
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(0 == memcmp(data, segment_1_data, filesz));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[2], &data, &filesz, &memsz) ;
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, sizeof(segment));
  ck_assert_int_eq(memsz, sizeof(segment));
  ck_assert(0 == memcmp(data, segment, sizeof(segment)));

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_addLoadSegment_offset_overlap_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  ret = libtwelf_open("../test_elfs/libtwelf_addLoadSegment_offset_overlap_output.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 3);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[0], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(0 == memcmp(data, segment_0_data, filesz));
  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[1], &data, &filesz, &memsz);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(0 == memcmp(data, segment_1_data, filesz));

  ret = libtwelf_getSegmentData(twelf, &twelf->segment_table[2], &data, &filesz, &memsz) ;
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(filesz, sizeof(segment));
  ck_assert_int_eq(memsz, sizeof(segment));
  ck_assert(0 == memcmp(data, segment, sizeof(segment)));

  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);

  free(segment_0_data);
  free(segment_1_data);
}
END_TEST

START_TEST (libtwelf_resolveSymbol_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  Elf64_Addr value;
  ret = libtwelf_resolveSymbol(twelf, "test", &value);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert_int_eq(value, 0x1337);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addSymbol_basic)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  ret = libtwelf_addSymbol(twelf, &twelf->section_table[1], "new_symbol", STT_OBJECT, 0xdeadbeef);
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addSymbol_basic_with_write)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/symtab.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 5);

  ret = libtwelf_addSymbol(twelf, &twelf->section_table[1], "new_symbol", STT_OBJECT, 0xdeadbeef);
  ck_assert_int_eq(ret, SUCCESS);

  ret = libtwelf_write(twelf, "../test_elfs/libtwelf_addSymbol_basic_with_write_output.elf");
  ck_assert_int_eq(ret, SUCCESS);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_addSymbol_without_symtab)
{
  struct LibtwelfFile *twelf;
  int ret = libtwelf_open("../test_elfs/simple.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);

  ck_assert_int_eq(twelf->number_of_segments, 2);
  ck_assert_int_eq(twelf->number_of_sections, 3);

  ret = libtwelf_addSymbol(twelf, &twelf->section_table[1], "new_symbol", STT_OBJECT, 0xdeadbeef);
  ck_assert_int_eq(ret, ERR_ELF_FORMAT);

  libtwelf_close(twelf);
}
END_TEST

int main(int argc, char** argv)
{
  Suite* suite = suite_create("Test suite");
  TCase* tcase = tcase_create("Test case");

  #define ADD_TESTCASE(name) {if (argc < 3 || !strcmp(#name, argv[2])) { tcase_add_test(tcase, name);} }


  ADD_TESTCASE(libtwelf_open_fail);
  ADD_TESTCASE(libtwelf_open_invalid_elf_header);
  ADD_TESTCASE(libtwelf_open_invalid_program_header);
  ADD_TESTCASE(libtwelf_open_invalid_section_header);
  ADD_TESTCASE(libtwelf_open_empty_elf);
  ADD_TESTCASE(libtwelf_open_filename);
  ADD_TESTCASE(libtwelf_open_segments_one);
  ADD_TESTCASE(libtwelf_open_section_name);
  ADD_TESTCASE(libtwelf_open_io);
  ADD_TESTCASE(libtwelf_write_fail);
  ADD_TESTCASE(libtwelf_write_basic);
  ADD_TESTCASE(libtwelf_write_simple);
  ADD_TESTCASE(libtwelf_write_symtab);
  ADD_TESTCASE(libtwelf_write_infiniteloop_mini);
  ADD_TESTCASE(libtwelf_write_gcc1);
  ADD_TESTCASE(libtwelf_write_orphaned_alloc_section);
  ADD_TESTCASE(libtwelf_getAssociatedSegment_basic);
  ADD_TESTCASE(libtwelf_getSectionData_basic);
  ADD_TESTCASE(libtwelf_getSegmentData_basic);
  ADD_TESTCASE(libtwelf_renameSection_fail);
  ADD_TESTCASE(libtwelf_renameSection_basic);
  ADD_TESTCASE(libtwelf_renameSection_basic_with_write);
  ADD_TESTCASE(libtwelf_setSegmentData_fail);
  ADD_TESTCASE(libtwelf_setSegmentData_invalid_args);
  ADD_TESTCASE(libtwelf_setSegmentData_basic);
  ADD_TESTCASE(libtwelf_setSegmentData_basic_with_write);
  ADD_TESTCASE(libtwelf_setSegmentData_overlapped_with_write);
  ADD_TESTCASE(libtwelf_setSectionData_fail);
  ADD_TESTCASE(libtwelf_setSectionData_invalid_args);
  ADD_TESTCASE(libtwelf_setSectionData_basic);
  ADD_TESTCASE(libtwelf_setSectionData_basic_with_write);
  ADD_TESTCASE(libtwelf_setSectionData_non_associated_with_write);
  ADD_TESTCASE(libtwelf_stripSymbols_basic);
  ADD_TESTCASE(libtwelf_stripSymbols_basic_with_write);
  ADD_TESTCASE(libtwelf_stripSymbols_without_symtab);
  ADD_TESTCASE(libtwelf_removeAllSections_basic);
  ADD_TESTCASE(libtwelf_removeAllSections_simple_with_write);
  ADD_TESTCASE(libtwelf_addLoadSegment_basic);
  ADD_TESTCASE(libtwelf_addLoadSegment_basic_with_write);
  ADD_TESTCASE(libtwelf_addLoadSegment_offset_overlap);
  ADD_TESTCASE(libtwelf_resolveSymbol_basic);
  ADD_TESTCASE(libtwelf_addSymbol_basic);
  ADD_TESTCASE(libtwelf_addSymbol_basic_with_write);
  ADD_TESTCASE(libtwelf_addSymbol_without_symtab);

  suite_add_tcase(suite, tcase);

  SRunner* suite_runner = srunner_create(suite);
  if (argc >= 2) {
    srunner_set_xml(suite_runner, argv[1]);
  }
  srunner_run_all(suite_runner, CK_VERBOSE);

  int ret = !!srunner_ntests_failed(suite_runner);
  srunner_free(suite_runner);

  return ret;
}
