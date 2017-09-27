#!/bin/bash

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
  scan-build -plist -o $ABS_REPORT_PATH/scan-build make > /dev/null 2>&1;
  make clean;
  popd;
done
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

# frama-c
echo 'Running Frama-C analyses...'
mkdir reports/frama-c;
# frama-c must analyze complementary testcases ending with '[abcde].c' together
partial_testcase_head_regex="[0-9]a\.c$"
partial_testcase_regex="[0-9][bcde]\.c$"
for c_file in `cat $C_FILES`; do
  if [[ $c_file =~ $partial_testcase_regex ]]; then
    continue;
  elif [[ $c_file =~ $partial_testcase_head_regex ]]; then
    target_files=`sed 's/a\.c$//'<<<$c_file`
    frama-c -val -value-log ew:reports/frama-c/framac_temp.log -kernel-log ew:reports/frama-c/framac_temp.log -cpp-extra-args='-Ijuliet/testcasesupport -DINCLUDEMAIN -U__cplusplus' juliet/testcasesupport/io.c ${target_files}*.c > /dev/null;
  else
    frama-c -val -value-log ew:reports/frama-c/framac_temp.log -kernel-log ew:reports/frama-c/framac_temp.log -cpp-extra-args='-Ijuliet/testcasesupport -DINCLUDEMAIN -U__cplusplus' juliet/testcasesupport/io.c $c_file > /dev/null;
  fi
  cat reports/frama-c/framac_temp.log >> reports/frama-c/frama-c.log;
  rm reports/frama-c/framac_temp.log
done;
printf "\tDone\n"

# flawfinder
echo 'Running flawfinder analyses...'
mkdir reports/flawfinder;
# we remove unwanted testcases to run flawfinder in the whole testsuite (this is faster)
cp -R juliet juliet_backup;
find  juliet/testcases | grep '/CWE[^/]*w32.*\.c$\|/CWE[^/]*wchar_t.*\.c$' | sort -u > c_testcases.toremove;
find  juliet/testcases | grep '/CWE[^/]*w32.*\.cpp$\|/CWE[^/]*wchar_t.*\.cpp$' | sort -u > cpp_testcases.toremove;
sort $C_FILES $C_FILES c_testcases.toremove | uniq -u | xargs rm
sort $CPP_FILES $CPP_FILES cpp_testcases.toremove | uniq -u | xargs rm
flawfinder juliet/testcasesupport -S juliet/testcases > reports/flawfinder/flawfinder.log;
rm -rf juliet
mv juliet_backup juliet
printf "\tDone\n"
