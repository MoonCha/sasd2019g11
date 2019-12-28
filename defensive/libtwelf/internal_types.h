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
  void *dummy;
};


struct LibtwelfSectionInternal
{
  void *dummy;
};
