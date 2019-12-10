///
/// DO NOT MODIFY THIS FILE
///
/// This library provides an interface to read and modify ELF files.
///
/// The following types of ELF files need to be handled:
///   - executable files
///   - object files
///
/// The following are NON-goals for this api
///   - handling of shared objects (shared libraries)
///   - handling of core dump files
///   - thread safety (accessing the same LibtwelfFile from multiple threads concurrently)
///   - portability: this library only needs to work on Linux with gcc or clang
///
/// The following are goals for this api
///  - memory safety (no buffer overflows, use-after-frees, use of unitialized values, ...)
///  - clean resource handling (no memory leaks, closing of opened files, ...)
///  - handling documented error cases gracefully
///    - for example if malloc fails the library shall return ERR_NOMEM and must
///      not leak any memory after libtwelf_close is called
///  - it must be possible to open multiple LibtwelfFiles simultaneously. 
///    it must also be possible to work with different LibtwelfFiles from different threads
///    Thus, no global variables shall be used
///  - handling integer overflows correctly
///  - readable code
///
/// Error cases:
///  - In case of errors, the data structures shall not be modified unless
///    specified otherwise.
///
/// This library hands out pointers to structs. Any user of this library must
/// not modify any value in these structs, otherwise the behavior is undefined.
///
/// It also provides a set of functions which modify the LibtwelfFile. These
/// shall not modify the file on disk, but rather act on the internal
/// representation of the file. Changes are committed to disk when libtwelf_write
/// is called.
///
/// DO NOT MODIFY THIS FILE
///
#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#include "libtwelf_types.h"


/// opens an elf file and checks its validity
///
/// @param file_name: the name of the file to be opened
/// @param result: outparam for the resulting file
///
/// The points for this function depend on libtwelf_close
///
/// To simplify functionality, a section must not overlap any PT_LOAD
/// segment or be fully contained within exactly one PT_LOAD segment.
///
/// errors:
/// ERR_IO opening/mapping the file failed
/// ERR_NOMEM memory allocation failed
/// ERR_ELF_FORMAT The LibtwelfFile is invalid, e.g.:
///                - any of the error cases defined in twelf.h
///                - file is smaller than the ELF header
///                - PT_LOAD segments overlap in virtual memory
///                - section not fully outside or fully contained within PT_LOAD segment
///                - section vaddr + size overflows uint64_t
///                - segment vaddr + memsz overflows uint64_t
///
int libtwelf_open(char *file_name, struct LibtwelfFile **result);


/// write the modified LibtwelfFile file to disk
///
/// Any field which was not modified by another libtwelf function must have the
/// same value in the output file as they had in the input file. (see twelf.h)
///
/// In the input file data that is referenced by sections may also be part of
/// a PT_LOAD segment. If this is the case this data shall only be stored once
/// in the output file. The same situation shall be considered when writing
/// non-PT_LOAD segments that might overlap PT_LOAD segments.
///
/// The particular layout of the output file on disk in unspecified, but the
/// segment/section contents must match those of the input file (unless modified
/// by libtwelf_setSegmentData/setSectionData). In particular there shall be no special
/// case for ELF files mapping their own ELF headers (the contents of the old
/// elf header shall be treated like any other data in the input file and thus
/// are written to the output file like any other segment data).
///
/// If the output file is the same file as the input file, the behaviour is
/// undefined.
///
/// In case of an error, the content of dest_file is unspecified.
///
/// errors:
/// ERR_IO: writing the file failed
/// ERR_NOMEM: memory allocation failed
///
int libtwelf_write(struct LibtwelfFile *twelf, char *dest_file);


/// Retrieve PT_LOAD segment to which section belongs. In particular,
/// find a segment that fully encloses the given section in virtual memory
/// i.e. segment.vaddr <=section.vaddr && segment.vaddr_end >= section.vaddr_end.
///
/// The result is stored in *result.
///
/// errors:
/// ERR_NOT_FOUND: no segment could be found
///
int libtwelf_getAssociatedSegment(struct LibtwelfFile *twelf, struct LibtwelfSection *section, struct LibtwelfSegment **result);


/// reads the content of a section and "returns" a pointer to the content in
/// *data. The length of the section is written to *len.
///
/// The memory pointed to by *data shall be valid at least until the next 
/// modifying API call (e.g. libtwelf_setSectionData), or until libtwelf_close is called.
///
/// When the section type is SHT_NOBITS (the type of the .bss section)
/// *data shall be set to NULL and *len to 0
///
int libtwelf_getSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char **data, size_t *len);


/// changes the name of the specified section. To achieve this, the section
/// holding the section names (.shstrtab) and the sh_name fields in the 
/// section headers need to be updated.
///
/// We assume that the .shstrtab section is only used for the
/// names of the sections.
///
/// To get bonus points, the generated .shstrtab section shall not waste space
/// i.e. each entry shall only require strlen(entry) + 1 bytes and there is no unused
/// space between entries.
///
/// errors:
/// ERR_NOMEM memory allocation failed
///
int libtwelf_renameSection(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *new_name);


/// provides the file content of a segment and "returns" a pointer to it in
/// *data. The file and memory size of the segment are written to *filesz and
/// *memsz respectively.
///
/// The memory pointed to by *data shall be valid for *filesz bytes.
///
/// The memory pointed to by *data shall be valid at least until the next 
/// modifying API call (e.g. libtwelf_setSegmentData), or until libtwelf_close is called.
///
int libtwelf_getSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char **data, size_t *filesz, size_t *memsz);

/// Updates a segment. In particular, sets new content, file size, and memory size for the specified segment.
/// Calling this function invalidates any pointer previously returned by
/// libtwelf_getSegmentData for that LibtwelfFile.
///
/// This function shall only work on segments that do not contain any sections.
///
/// This function copies the memory pointed to by data into an internal buffer.
/// Thus the caller is responsible for cleanup of memory referenced by the data
/// parameter.
///
/// errors:
///   ERR_NOMEM memory allocation failed
///   ERR_INVALID_ARG segment contains sections
///   ERR_INVALID_ARG segments would overlap in virtual memory
///   ERR_INVALID_ARG filesz is larger than memsz
///
int libtwelf_setSegmentData(struct LibtwelfFile *twelf, struct LibtwelfSegment *segment, const char *data, size_t filesz, size_t memsz);

/// sets new data and size for the specified section.
///
/// If the section has an associated PT_LOAD segment (i.e. overlapping
/// virtual memory), the segment's data is also affected. In particular, 
/// a call to libtwelf_getSegmentData shall return the modified segment data.
///
/// When shrinking a section associated to a PT_LOAD segment, the freed data
/// shall be zeroed out in the segment.
///
/// To simplify functionality, if the section is covered by a non-PT_LOAD
/// segment, the data for this segment is unspecified.
///
/// This function shall fail if enlarging the section would create an overlap
/// with another section, or would grow beyond the size of the associated segment, if any.
///
/// This function copies the memory pointed to by data into an internal buffer.
/// Thus the caller is responsible for cleanup of memory referenced by the data
/// parameter.
///
/// errors:
/// ERR_NOMEM memory allocation failed
/// ERR_INVALID_ARG section resize not possible
///
int libtwelf_setSectionData(struct LibtwelfFile *twelf, struct LibtwelfSection *section, const char *data, size_t size);

/// closes the elf file and frees all associated resources
///
void libtwelf_close(struct LibtwelfFile *twelf);


/// removes all symbols from the file by removing the .symtab section and the
/// section it links to (this is usually the .strtab section).
///
/// If these sections have an overlapping segment (PT_LOAD or non-PT_LOAD),
/// the result for such segments is unspecified.
///
/// This function may invalidate all pointers derived from twelf->section_table.
///
/// erorrs:
///   ERR_NOMEM memory allocation failed, and the LibtwelfFile might not have stripped both sections.
///   ERR_ELF_FORMAT no .symtab section found
///   ERR_ELF_FORMAT .symtab does not link to another section
///
int libtwelf_stripSymbols(struct LibtwelfFile *twelf);


/// removes all sections from the specified LibtwelfFile.
/// Subsequent calls to libtwelf_write shall not write any section headers.
/// 
/// This function may invalidate all pointers derived from twelf->section_table.
///
/// Segment data shall remain unmodified. Thus, section data may still be
/// present in the output file if it is part of a segment. This allows a
/// LibtwelfFile to be executed even after removing all sections.
/// 
int libtwelf_removeAllSections(struct LibtwelfFile *twelf);


/// adds a new segment and its content to the LibtwelfFile.
///
/// The new segment shall have type PT_LOAD, and segments shall be
/// sorted according to their virtual address.
///
/// This function may invalidate all pointers derived from twelf->segment_table.
///
/// In case of error the LibtwelfFile should not be modified.
///
/// errors:
/// ERR_INVALID_ARG flags is not a bit combination of PF_R, PF_W and PF_X
/// ERR_INVALID_ARG segments would overlap in virtual memory
/// ERR_NOMEM: memory allocation failed
///
int libtwelf_addLoadSegment(struct LibtwelfFile *twelf, char *data, size_t len, uint32_t flags, Elf64_Addr vaddr);

/// BONUS
/// resolves a symbol in the .symtab and retrieves its value
///
/// errors:
/// ERR_NOT_FOUND: symbol could not be found
/// ERR_ELF_FORMAT: ELF file has no .symtab section
///
int libtwelf_resolveSymbol(struct LibtwelfFile *twelf, const char *name, Elf64_Addr *st_value);

/// BONUS
/// adds a new symbol to the LibtwelfFile
///
/// type shall be one of STT_FUNC or STT_OBJECT
/// st_info shall be ELF32_ST_INFO(STB_GLOBAL, type)
//
/// st_other shall be STV_DEFAULT
/// st_size shall be 0
///
/// errors:
/// ERR_NOMEM: memory allocation failed
/// ERR_ELF_FORMAT: ELF file has no .symtab section
///
int libtwelf_addSymbol(struct LibtwelfFile *twelf, struct LibtwelfSection* section, const char *name, unsigned char type, Elf64_Addr st_value);

///
/// DO NOT MODIFY THIS FILE
///
