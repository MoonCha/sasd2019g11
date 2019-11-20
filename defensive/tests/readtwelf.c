#include <stdio.h>
#include <string.h>


#include "twelf.h"
#include "libtwelf.h"

void printSegments(struct LibtwelfFile *twelf);
void printSections(struct LibtwelfFile *twelf);

int main(int argc, char **argv)
{
  struct LibtwelfFile *twelf;
  int ret;

  if (argc < 2)
  {
    printf("usage: %s <executable> [additional args]\n", argv[0]);
    return 1;
  }

  ret = libtwelf_open(argv[1], &twelf);
  if (ret != 0)
  {
    printf("could not load elf file\n");
    goto cleanup;
  }

  if (twelf->number_of_sections > 2)
    libtwelf_renameSection(twelf, twelf->section_table + 2, "section2");

  printSegments(twelf);
  printSections(twelf);

  char segment[] = {0x6a, 0x68, 0x48, 0xb8, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x2f, 0x73, 0x50, 0x48, 0x89, 0xe7, 0x68, 0x72, 0x69, 0x1, 0x1, 0x81, 0x34, 0x24, 0x1, 0x1, 0x1, 0x1, 0x31, 0xf6, 0x56, 0x6a, 0x8, 0x5e, 0x48, 0x1, 0xe6, 0x56, 0x48, 0x89, 0xe6, 0x31, 0xd2, 0x6a, 0x3b, 0x58, 0xf, 0x5};

  if ((ret = libtwelf_addLoadSegment(twelf, segment, sizeof(segment), PF_R | PF_X, 0x414141414141ull)))
    printf("addLoadSegment failed (%d)\n", ret);

  if ((ret = libtwelf_write(twelf, "/tmp/libtwelf_outbasic")))
    printf("write with additional segment failed (%d)\n", ret);

  if ((ret = libtwelf_stripSymbols(twelf)))
    printf("stripSymbols failed (%d)\n", ret);

  if ((ret = libtwelf_write(twelf, "/tmp/libtwelf_nosyms")))
    printf("write nosyms failed (%d)", ret);

  if ((ret = libtwelf_removeAllSections(twelf)))
    printf("removeAllSections failed (%d)\n", ret);

  if ((ret = libtwelf_write(twelf, "/tmp/libtwelf_stripped")))
    printf("write stripped failed (%d)\n", ret);

cleanup:
  libtwelf_close(twelf);
  return ret;
}

void printSegments(struct LibtwelfFile *twelf)
{
  printf("number of segments: %zd\n", twelf->number_of_segments);

  for (size_t i = 0; i < twelf->number_of_segments; ++i)
  {
    struct LibtwelfSegment *segment = twelf->segment_table + i;
    char perms[4] = "";
    if (segment->readable)
      strcat(perms, "r");
    if (segment->writeable)
      strcat(perms, "w");
    if (segment->executable)
      strcat(perms, "x");

    char *type = "UNKOWN";
    switch(segment->type)
    {
case PT_LOAD:
      type = "LOAD";
      break;
case PT_DYNAMIC:
      type = "DYNAMIC";
      break;
case PT_NOTE:
      type = "NOTE";
      break;
case PT_TLS:
      type = "TLS";
      break;
case PT_GNU_STACK:
      type = "GNU_STACK";
      break;
    }

    printf("%10s %s\n", type, perms);
  }
}

void printSections(struct LibtwelfFile *twelf)
{
  printf("number of sections: %zd\n", twelf->number_of_sections);

  // the zero'th section is always null
  for (size_t i = 1; i < twelf->number_of_sections; ++i)
  {
    struct LibtwelfSection *section = twelf->section_table + i;

    printf("%s\n", section->name ? section->name : "(NULL)");
    if (section->flags & SHF_ALLOC)
    {
      printf("  memory: 0x%016lx -- 0x%016lx\n",
             section->address, section->address + section->size);
    }
  }
}
