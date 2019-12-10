# Assignment 2: Libtwelf

## Building and testing

If you do not want to install the tools on your local machine, you can use the docker image by running:

```
./docker.sh run
```

You will need a build directory and execute cmake:

```
mkdir build
cd build
cmake ..
```

Now you can build and run your project:

```
make all                                   # build your project
make test                                  # run all testcases
make test-fast                             # run all testcases except valgrind tests
make test-verbose                          # run all testcases with full output
make test-single testcase=<testcase name>  # run single testcase by name (with full output)
make gcov                                  # run coverage analysis on last `make test` run
                                           # (output HTML files will be in /build/coverage_report/)
```

Examples:

```
make test-single testcase=libtwelf_open_empty_elf  # run libtwelf_open_empty_elf testcase
make all test-fast gcov                            # compile, run tests and generate coverage analysis
```

## Using AFL

Setting the CMake variable `ENABLE_AFL` to 1 will enable instrumentation to guide the AFL fuzzer.

From the build directory:
```
cmake -DENABLE_AFL=1 -DENABLE_SCAN_BUILD=0 ..
make
```

Your code has now been built with instrumentation and is ready to fuzz:
```
mkdir afl_input
cp some.elf testcase.elf files.elf afl_input/
make afl
```

Output from AFL lands in `afl_output/`

## Using the Clang static analyzer

From the build directory:
```
cmake -DENABLE_AFL=0 -DENABLE_SCAN_BUILD=1 ..
make clean && scan-build make
```

This should take longer than a normal build, and at the end, if potential issues were found, output
the following messages:
```
scan-build: 20 bugs found.
scan-build: Run 'scan-view /tmp/scan-build-...' to examine bug reports.
```

Running the command which is output by `scan-build` allows you to view the potential issues in a web
browser. Note that there may be false positives among them.

## Disabling AFL and Clang static analyzer

You can disable AFL instrumentation and static analysis of your code by setting the respective
CMake variables to 0:
```
cmake -DENABLE_AFL=0 -DENABLE_SCAN_BUILD=0 ..
```


## Writing testcases

### Test variants

To add a testcase you need to define a function (using `START_TEST` and `END_TEST`) and add it to the testsuite
(using `ADD_TESTCASE`) in `testsuite/testcases.c`. After that you will need to rerun
```
cmake ..
```
and cmake will add your testcase in three versions (normal, asan and valgrind).

### Test ELFs
You may want to create ELF files as input for your testcases.
In `/test_elfs` we provide you with example assembly files which can be used to create very simple ELF files.
You may create your own test assembly files and compile them by extending `/test_elfs/generate.sh`.

Note: You are not required to use assembly files to create your test elfs.
