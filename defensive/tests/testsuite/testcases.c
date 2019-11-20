#include <stdio.h>
#include <stdlib.h>
#include <check.h>
#include <twelf.h>
#include <malloc.h>

#include "libtwelf.h"
#include "alloc_wrapper.h"


START_TEST (libtwelf_open_empty_elf)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert(ret == SUCCESS);

  ck_assert(twelf->number_of_segments == 0);
  ck_assert(twelf->number_of_sections == 0);

  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_filename)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/empty.elf", &twelf);
  ck_assert(ret == 0);
  ck_assert_str_eq("../test_elfs/empty.elf", twelf->file_name);
  libtwelf_close(twelf);
}
END_TEST

START_TEST (libtwelf_open_segments_one)
{
  struct LibtwelfFile *twelf = NULL;
  int ret = libtwelf_open("../test_elfs/infiniteloop_mini.elf", &twelf);
  ck_assert_int_eq(ret, SUCCESS);
  ck_assert(ret == SUCCESS);
  ck_assert(twelf->number_of_segments == 1);
  ck_assert(twelf->segment_table[0].type == PT_LOAD);
  ck_assert(twelf->segment_table[0].vaddr == 0x0000000000010000);
  ck_assert(twelf->segment_table[0].filesize == 0x000000000000007a);
  ck_assert(twelf->segment_table[0].memsize == 0x0000000000001000);
  ck_assert(twelf->segment_table[0].readable == true);
  ck_assert(twelf->segment_table[0].writeable == true);
  ck_assert(twelf->segment_table[0].executable == true);
  libtwelf_close(twelf);
}
END_TEST


int main(int argc, char** argv)
{
  Suite* suite = suite_create("Test suite");
  TCase* tcase = tcase_create("Test case");

  #define ADD_TESTCASE(name) {if (argc < 3 || !strcmp(#name, argv[2])) { tcase_add_test(tcase, name);} }


  ADD_TESTCASE(libtwelf_open_empty_elf);
  ADD_TESTCASE(libtwelf_open_filename);
  ADD_TESTCASE(libtwelf_open_segments_one);

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
