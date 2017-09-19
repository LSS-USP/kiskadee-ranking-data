#!/bin/sh

if [ ! -d  juliet ]; then
  mkdir juliet;
  wget 'https://samate.nist.gov/SRD/testsuites/juliet/Juliet_Test_Suite_v1.2_for_C_Cpp.zip';
  unzip -d juliet Juliet_Test_Suite_v1.2_for_C_Cpp.zip > /dev/null;
  pushd juliet;
  # This patch fixes some bugs in the provided python scripts to run tools on specific test cases
  patch -p1 < ../00-fix-python-scripts.patch;
  popd;
  rm Juliet_Test_Suite_v1.2_for_C_Cpp.zip;
fi

