#!/usr/bin/python3

# Script that runs each static analyzer in each test case used for
# our experiments.

import sys
import os

# add parent directory to search path so we can use py_common
sys.path.append('juliet')

import py_common

def run_command(command):
    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_cppcheck(testcase):
    command = ['cppcheck', '--xml', '--xml-version=2', '-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport', testcase]
    run_command(command)

def run_flawfinder(testcase):
    command = ['flawfinder', testcase]
    run_command(command)

def run_framac(testcase):
    # frama-c -val -value-log ew:/tmp/frama.log -cpp-extra-args="-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport -DINCLUDEMAIN" CWE369_Divide_by_Zero__float_connect_socket_01.c

    # frama-c -val -value-log ew:/tmp/frama.log -cpp-extra-args="-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport -DINCLUDEMAIN" CWE126_Buffer_Overread__malloc_wchar_t_memmove_66b.c CWE126_Buffer_Overread__malloc_wchar_t_memmove_66a.c /home/athos/USP/pesquisa/experiments/juliet/testcasesupport/io.c
    command = ['frama-c', '-val', '-value-log', 'ew:/tmp/'+testcase+'.log', '-kernel-log', 'ew:/tmp/'+testcase+'.log', '-cpp-extra-args=-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport -DINCLUDEMAIN', testcase]

    py_common.print_with_timestamp("Running " + ' '.join(command))
    py_common.run_commands(command)

def run_scanbuild(testcase):
    #command = ['scan-build', 'clang', '-DINCLUDEMAIN', '-I/home/athos/USP/pesquisa/experiments/juliet/testcasesupport', testcase, '/home/athos/USP/pesquisa/experiments/juliet/testcasesupport/io.c']
    command = ['scan-build', 'make']
    run_command(command)

def run_print_filename(testcase):
    command = ['echo', testcase]
    run_command(command)

def run_cleanup(testcase):
    command = ['make', 'clean']
    run_command(command)

if __name__ == '__main__':

    #os.chdir('juliet')
    # Analyze the test cases
    directory = 'juliet/testcases'
    regex = "CWE126.*\.c$"
    py_common.run_analysis(directory, regex, run_framac)
    py_common.run_analysis(directory, regex, run_cppcheck)
    py_common.run_analysis(directory, regex, run_flawfinder)
    py_common.run_analysis('testcases', 'Makefile', run_scanbuild)
    py_common.run_analysis('testcases', 'Makefile', run_cleanup)
