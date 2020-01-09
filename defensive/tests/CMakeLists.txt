file(GLOB twelf_sources *.c *.S)

pkg_search_module(CHECK REQUIRED check)

include_directories(${CHECK_INCLUDE_DIRS})
set(LIBS ${LIBS} libfaultinject ${CHECK_LIBRARIES} pthread)
set(ASAN_OPTIONS -fno-omit-frame-pointer -fsanitize=address,undefined,leak)

FOREACH(curFile ${twelf_sources})
  GET_FILENAME_COMPONENT(curName ${curFile} NAME_WE)
  ADD_EXECUTABLE(${curName} ${curFile})
  TARGET_LINK_LIBRARIES(${curName} libtwelf ${LIBS})

  ADD_EXECUTABLE(${curName}_asan ${curFile})
  TARGET_LINK_LIBRARIES(${curName}_asan libtwelf_asan ${LIBS})
  TARGET_COMPILE_OPTIONS(${curName}_asan PUBLIC ${ASAN_OPTIONS})
  TARGET_LINK_OPTIONS(${curName}_asan PUBLIC ${ASAN_OPTIONS})
ENDFOREACH()

file(GLOB twelf_projects */)
FOREACH(curProject ${twelf_projects})
  FILE(GLOB curProject_sources ${curProject}/*.c ${curProject}/*.S)
  GET_FILENAME_COMPONENT(curName ${curProject} NAME_WE)

  IF(IS_DIRECTORY ${curProject})
    ADD_EXECUTABLE(${curName} ${curProject_sources})
    TARGET_LINK_LIBRARIES(${curName} libtwelf ${LIBS})

    ADD_EXECUTABLE(${curName}_asan ${curProject_sources})
    TARGET_LINK_LIBRARIES(${curName}_asan libtwelf_asan ${LIBS})
    TARGET_COMPILE_OPTIONS(${curName}_asan PUBLIC ${ASAN_OPTIONS})
    TARGET_LINK_OPTIONS(${curName}_asan PUBLIC ${ASAN_OPTIONS})
  ENDIF()
ENDFOREACH()

TARGET_LINK_LIBRARIES(testsuite dl)
TARGET_LINK_LIBRARIES(testsuite_asan dl)


TARGET_LINK_OPTIONS(testsuite PUBLIC -rdynamic
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=strdup
    -Wl,--wrap=open
    -Wl,--wrap=fopen
    -Wl,--wrap=close
    -Wl,--wrap=fclose
    -Wl,--wrap=fstat
    -Wl,--wrap=fseek
    -Wl,--wrap=ftell
    -Wl,--wrap=fread
    -Wl,--wrap=fwrite
    -Wl,--wrap=read
    -Wl,--wrap=write
    -Wl,--wrap=mmap)
TARGET_LINK_OPTIONS(testsuite_asan PUBLIC -rdynamic
    -Wl,--wrap=malloc
    -Wl,--wrap=calloc
    -Wl,--wrap=realloc
    -Wl,--wrap=strdup
    -Wl,--wrap=open
    -Wl,--wrap=fopen
    -Wl,--wrap=close
    -Wl,--wrap=fclose
    -Wl,--wrap=fstat
    -Wl,--wrap=fseek
    -Wl,--wrap=ftell
    -Wl,--wrap=fread
    -Wl,--wrap=fwrite
    -Wl,--wrap=read
    -Wl,--wrap=write
    -Wl,--wrap=mmap)

enable_testing()

execute_process (
    COMMAND bash -c "grep ADD_TESTCASE ${CMAKE_CURRENT_SOURCE_DIR}/testsuite/*.c | grep -v '#define' | grep -Po '\\(\\K[^)]*' | tr '\n' ' '"
    OUTPUT_VARIABLE testcase_names
)

separate_arguments(testcase_names)

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fprofile-arcs -ftest-coverage")
set (CMAKE_LINKER_FLAGS "${CMAKE_LINKER_FLAGS} -fprofile-arcs")
set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fprofile-arcs -lgcov")

find_program(VALGRIND valgrind)
find_program(LCOV lcov)
find_program(GENHTML genhtml)
set(VALGRIND_ARGUMENTS --tool=memcheck --leak-check=yes --leak-resolution=high
  --show-reachable=yes --show-leak-kinds=all --error-exitcode=42
  --suppressions=${CMAKE_SOURCE_DIR}/tests/valgrind.supp --errors-for-leak-kinds=all
  --child-silent-after-fork=yes)
set(VALGRIND_ENV CK_FORK=no)
set(LCOV_FLAGS --capture --rc lcov_branch_coverage=1)
set(GENHTML_FLAGS --rc lcov_branch_coverage=1)
set(CTEST_OUTPUT_ON_FAILURE 1)

add_custom_target(gcov
                  COMMAND zsh -c "rm **/util.c.gcda" 2> /dev/null || true # ignore util.c
                  COMMAND ${LCOV} ${LCOV_FLAGS} --output-file gcov.info --base-directory ${PROJECT_SOURCE_DIR} --directory libtwelf
                  COMMAND ${GENHTML} ${GENHTML_FLAGS} --output-directory coverage_report gcov.info > gcov.log
                  COMMAND echo -e '\\033[1;34mCoverage report has been written to ./coverage_report\\033[0m'
                  COMMAND echo -e '\\033[1;34mYou can inspect it with a web browser of your choice.\\033[0m'
                  WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")

add_custom_target(test-fast
                  COMMAND ${CMAKE_CTEST_COMMAND} -E "_valgrind")

add_custom_target(test-verbose
                  COMMAND ${CMAKE_CTEST_COMMAND} -V)

add_custom_target(test-single
                  COMMAND ${CMAKE_CTEST_COMMAND} -V -R \${testcase}\\\$)

add_custom_target(test-direct
                  COMMAND ${CMAKE_CURRENT_BINARY_DIR}/testsuite ${CMAKE_CURRENT_BINARY_DIR}/out.xml \${testcase})

add_custom_target(cppcheck
                  COMMAND cppcheck --enable=warning libtwelf
                  WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}")

add_custom_target(afl
                  COMMAND "${PROJECT_SOURCE_DIR}/tests/afl.sh"
                  WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")

FOREACH(tc ${testcase_names})
  execute_process (
    COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/${tc}.xml
    COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/${tc}_asan.xml
    COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/valgrind-${tc}.xml
    COMMAND touch ${CMAKE_CURRENT_BINARY_DIR}/valgrind-${tc}_vgout.xml
  )
  add_test(NAME ${tc}
           COMMAND ${CMAKE_CURRENT_BINARY_DIR}/testsuite ${CMAKE_CURRENT_BINARY_DIR}/${tc}.xml ${tc}
           WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
  add_test(NAME ${tc}_asan
           COMMAND ${CMAKE_CURRENT_BINARY_DIR}/testsuite_asan ${CMAKE_CURRENT_BINARY_DIR}/${tc}_asan.xml ${tc}
           WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
  add_test(NAME "${tc}_valgrind"
           COMMAND ${CMAKE_COMMAND} -E env ${VALGRIND_ENV} ${VALGRIND} ${VALGRIND_ARGUMENTS} --xml=yes --xml-file=${CMAKE_CURRENT_BINARY_DIR}/valgrind-${tc}_vgout.xml ${CMAKE_CURRENT_BINARY_DIR}/testsuite ${CMAKE_CURRENT_BINARY_DIR}/valgrind-${tc}.xml ${tc}
           WORKING_DIRECTORY "${PROJECT_BINARY_DIR}")
ENDFOREACH()
