#!/bin/sh

./bootstrap.sh

C_FILES=c_testcases.list
CPP_FILES=cpp_testcases.list
rm -rf reports
mkdir reports;

# clang static analyzer
mkdir reports/scan-build;
pushd juliet;
scan-build -o reports/scan-build make -f Makefile_all;
make -f Makefile_all clean;
popd;

# frama-c
mkdir reports/frama-c;
cat $C_FILES $CPP_FILES | xargs frama-c -val -value-log ew:reports/frama-c/frama-c.log -kernel-log ew:reports/frama-c/frama-c.log -cpp-extra-args='-Ijuliet/testcasesupport -lpthread' juliet/testcasesupport/std_thread.c juliet/testcasesupport/io.c juliet/testcasesupport/main_linux.cpp;
make -f Makefile_all clean;

# cppcheck
mkdir reports/cppcheck;
cat $C_FILES $CPP_FILES > cppcheck.list;
echo juliet/testcasesupport/std_thread.c >> cppcheck.list
echo juliet/testcasesupport/io.c >> cppcheck.list
echo juliet/testcasesupport/main_linux.cpp >> cppcheck.list
cppcheck -I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport --file-list=cppcheck.list 2> reports/cppcheck/cppcheck.log;
rm cppcheck.list;

# flawfinder
mkdir reports/flawfinder;
cat $C_FILES $CPP_FILES | xargs flawfinder --savehitlist reports/flawfinder/flawfinder.log juliet/testcasesupport/std_thread.c juliet/testcasesupport/io.c juliet/testcasesupport/main_linux.cpp;
