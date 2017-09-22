#!/bin/sh

C_FILES=c_testcases.list
CPP_FILES=cpp_testcases.list
ABS_REPORT_PATH=$PWD/reports
rm -rf reports
mkdir reports;

# clang static analyzer
echo 'Running scan-build (clang analyzer) analyses...'
mkdir reports/scan-build;
for mkfile in `cat $C_FILES $CPP_FILES | xargs -l -n1 dirname | sort -u`; do
  pushd $mkfile;
  scan-build -o $ABS_REPORT_PATH/scan-build make > /dev/null 2>&1;
  make clean;
  popd;
done
printf "\tDone\n"

# frama-c
echo 'Running Frama-C analyses...'
mkdir reports/frama-c;
for c_file in `cat $C_FILES`; do
  frama-c -val -value-log ew:reports/frama-c/framac.log -kernel-log ew:reports/frama-c/framac.log -cpp-extra-args='-Ijuliet/testcasesupport -DINCLUDEMAIN -U__cplusplus' juliet/testcasesupport/io.c $c_file > /dev/null;
  cat reports/frama-c/framac.log >> reports/frama-c/all.log;
done;
make -f Makefile_all clean;
printf "\tDone\n"

# cppcheck
echo 'Running cppcheck analyses...'
mkdir reports/cppcheck;
cat $C_FILES $CPP_FILES > cppcheck.list;
echo juliet/testcasesupport/std_thread.c >> cppcheck.list
echo juliet/testcasesupport/io.c >> cppcheck.list
echo juliet/testcasesupport/main_linux.cpp >> cppcheck.list
cppcheck -I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport --file-list=cppcheck.list 2> reports/cppcheck/cppcheck.log 1> /dev/null;
rm cppcheck.list;
printf "\tDone\n"

# flawfinder
echo 'Running flawfinder analyses...'
mkdir reports/flawfinder;
for source_file in `cat $C_FILES $CPP_FILES`; do
  flawfinder juliet/testcasesupport/std_thread.c juliet/testcasesupport/io.c juliet/testcasesupport/main_linux.cpp $source_file >> reports/flawfinder/flawfinder.log;
done;
printf "\tDone\n"
