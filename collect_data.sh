#!/bin/sh

C_FILES=c_testcases.list
CPP_FILES=cpp_testcases.list

printf "Total number of test cases in Juliet: %s\n" \
`find juliet/testcases -regex '.*[0-9a]\.c[p]*$' | wc -l`

printf "Number of C test cases in Juliet: %s\n" \
`find juliet/testcases -regex '.*[0-9a]\.c$' | wc -l`

printf "Number of C++ test cases in Juliet: %s\n" \
`find juliet/testcases -regex '.*[0-9a]\.cpp$' | wc -l`

printf "Number of CWEs covered in juliet: %s\n" \
`ls juliet/testcases | wc -l`

printf "Number of C test cases used in this experiment: %s\n" \
`cat $C_FILES | grep '.*[0-9a]\.c$' | wc -l`
echo "\tthis excludes windows specific test cases"

printf "Number of C++ test cases used in this experiment: %s\n" \
`cat $CPP_FILES | grep '.*[0-9a]\.cpp$' | wc -l`
echo "\tthis excludes windows specific test cases"

printf "Number of different Juliet CWEs analyzed in this experiment: %s\n" \
`cat c_testcases.list cpp_testcases.list | cut -d / -f3 | sort -u | wc -l`
echo "\tthis excludes CWEs containing only windows specific test cases"

printf "Number of CWEs convered on the C test cases used %s\n" \
`cat c_testcases.list | cut -d / -f3 | sort -u | wc -l`

printf "Number of CWEs convered on the C++ test cases used %s\n" \
`cat cpp_testcases.list | cut -d / -f3 | sort -u | wc -l`

echo 'Version of static analyzers:'
# This is RPM distro specific and could be improved
printf "\tFrama-C: %s\n" \
`rpm -qi frama-c | grep Version | awk '{ print $3 }'`
# flawfinder
printf "\tflawfinder: %s\n" \
`rpm -qi flawfinder | grep Version | awk '{ print $3 }'`
printf "\tcppcheck: %s\n" \
`rpm -qi cppcheck | grep Version | awk '{ print $3 }'`
# scan-build
printf "\tscan-build (Clang Analyzer): %s\n" \
`rpm -qi clang-analyzer | grep Version | awk '{ print $3 }'`

python firehose_report_parser stats
