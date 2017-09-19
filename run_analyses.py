#!/usr/bin/python3

# Script that runs each static analyzer in each test case used for
# our experiments.

import sys
import os

# add parent directory to search path so we can use py_common
sys.path.append('juliet')

import py_common


def run_cppcheck(testcase):
    command = ['cppcheck', '--xml', '--xml-version=2', '-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport', testcase]

    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_flawfinder(testcase):
    command = ['flawfinder', testcase]

    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_scanbuild(testcase):
    #command = ['scan-build', 'clang', '-DINCLUDEMAIN', '-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport', testcase, '/home/athos/USP/pesquisa/experiments/juliet/testcasesupport/io.c']
    command = ['scan-build', 'make']

    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_print_filename(testcase):
    command = ['echo', testcase]
    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_cleanup(testcase):
    command = ['make', 'clean']

    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)



if __name__ == '__main__':

    os.chdir('juliet')
    # Analyze the test cases
    directory = 'testcases'
    regex = "CWE126.*\.c$"
    py_common.run_analysis(directory, regex, run_cppcheck)
    py_common.run_analysis(directory, regex, run_flawfinder)
    py_common.run_analysis('testcases', 'Makefile', run_scanbuild)
    py_common.run_analysis('testcases', 'Makefile', run_cleanup)
