///
/// specification of the types used in the public interface of libtwelf
///
/// DO NOT MODIFY THIS FILE
///

#pragma once

#include "twelf.h"
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

// defined in internal_types.h
struct LibtwelfFileInternal;
struct LibtwelfSegmentInternal;
struct LibtwelfSectionInternal;
struct LibtwelfSymbolInternal;


/// take a look at the each function definition to determine which error code
/// to return
///
enum LibtwelfError
{
  SUCCESS = 0,

  // generic errors
  ERR_NOT_IMPLEMENTED = 1,
  ERR_IO = 2,               /// Errors related to file I/O
  ERR_NOMEM = 3,            /// Out of memory
  ERR_INVALID_ARG = 4,      /// NULL pointer arguments, etc.

  // elf file specific errors
  ERR_ELF_FORMAT = 5,       /// ELF parsing errors
  ERR_NOT_FOUND = 6,        /// If a requested object cannot be located
};

struct LibtwelfFile
{
  /// the name of the file that was read
  char *file_name;

  /// contains an entry for each segment in the read file
  struct LibtwelfSegment *segment_table;
  /// the number of entries in @ref segment_table;
  size_t number_of_segments;


  /// contains an entry for each section in the read file
  struct LibtwelfSection *section_table;
  /// the number of entries in @ref section table;
  size_t number_of_sections;

  /// for internal use only
  struct LibtwelfFileInternal *internal;
};

///
/// describes a segment i.e. the unit of the binary that is processed by the
/// loader (for example the linux kernel or ld.so)
///
struct LibtwelfSegment
{
  uint32_t type;
  uint64_t vaddr;
  uint64_t filesize;
  uint64_t memsize;

  bool readable;
  bool writeable;
  bool executable;

  /// for internal use only
  struct LibtwelfSegmentInternal *internal;
};

///
/// describes a section i.e. the unit of the binary processed by the program linker
/// sections are not strictly necessary for execution a binary/shared object but
/// are still present anyway
///
struct LibtwelfSection
{
  /// the name of the section
  /// the ELF section header contains an index into the .shstrtab section,
  /// where a null terminated string is stored
  char *name;

  /// the address of the section in virtual memory as specified in the
  /// section header
  uint64_t address;

  /// the size of the section as specified in the section header
  uint64_t size;

  /// the type of the section as specified in the section header
  uint32_t type;

  /// the flags of the section as specified in the section header
  uint32_t flags;

  /// the linked section, which is derived from the sh_num field in the section
  /// header
  /// This is used for example to link a symbol table to its corresponding
  /// string table
  struct LibtwelfSection *link;

  struct LibtwelfSectionInternal *internal;
};

///
/// DO NOT MODIFY THIS FILE
///
