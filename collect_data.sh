#!/bin/sh

C_FILES=c_testcases.list
CPP_FILES=cpp_testcases.list

# Total number of test cases in juliet
find juliet/testcases -regex '.*[0-9a]\.c[p]*$' | wc -l

# Number of c test cases in juliet
find juliet/testcases -regex '.*[0-9a]\.c$' | wc -l

# Number of cpp test cases in juliet
find juliet/testcases -regex '.*[0-9a]\.cpp$' | wc -l

# Number of CWEs covered in juliet
ls juliet/testcases | wc -l

# Number of c test cases used in this experiment
# this excludes windows specific test cases
cat $C_FILES | grep '.*[0-9a]\.c$' | wc -l

# Number of cpp test cases used in this experiment
# this excludes windows specific test cases
cat $CPP_FILES | grep '.*[0-9a]\.cpp$' | wc -l

# Number of CWEs covered in juliet used in this experiment
# this excludes CWEs containing only windows specific test cases
cat c_testcases.list cpp_testcases.list | cut -d / -f3 | sort -u | wc -l
# number of them convered on c test cases
cat c_testcases.list | cut -d / -f3 | sort -u | wc -l
# number of them convered on cpp test cases
cat cpp_testcases.list | cut -d / -f3 | sort -u | wc -l

# Version of static analyzers
# This is RPM distro specific and could be improved
# frama-c
rpm -qi frama-c | grep Version | awk '{ print $3 }'
# flawfinder
rpm -qi flawfinder | grep Version | awk '{ print $3 }'
# cppcheck
rpm -qi cppcheck | grep Version | awk '{ print $3 }'
# scan-build
rpm -qi clang-analyzer | grep Version | awk '{ print $3 }'

# Total number of warnings triggered
# this must come from the firehose parser
