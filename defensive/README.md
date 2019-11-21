# Assmignment 2: Libtwelf

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
make test-verbose                          # run all testcases with full output
make test-single testcase=<testcase name>  # run single testcase by name (with full output)
make gcov                                  # run coverage analysis (output HTML files will be in /build/coverage_report/)
```

Examples:

```
make test-single testcase=libtwelf_open_empty_elf  # run libtwelf_open_empty_elf testcase
make all test gcov                                 # compile, run tests and generate coverage analysis
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
