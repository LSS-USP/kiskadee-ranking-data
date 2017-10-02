#!/bin/sh

if [ ! -d  juliet ]; then
  if [ ! -f /usr/bin/wget ]; then
    echo 'Please, install wget and run again';
    exit 1;
  fi
  mkdir juliet;
  wget 'https://samate.nist.gov/SRD/testsuites/juliet/Juliet_Test_Suite_v1.2_for_C_Cpp.zip';
  unzip -d juliet Juliet_Test_Suite_v1.2_for_C_Cpp.zip > /dev/null;
  rm Juliet_Test_Suite_v1.2_for_C_Cpp.zip;
fi

# get c and cpp file lists
find  juliet/testcases | grep -v '/CWE[^/]*w32.*\.c$\|/CWE[^/]*wchar_t.*\.c$' | grep '/CWE[^/]*\.c$' | sort -u > c_testcases.list;
find  juliet/testcases | grep -v '/CWE[^/]*w32.*\.cpp$\|/CWE[^/]*wchar_t.*\.cpp$' | grep '/CWE[^/]*\.cpp$' | sort -u > cpp_testcases.list;

