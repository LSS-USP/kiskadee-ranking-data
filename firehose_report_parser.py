"""
Use this same file to aggregate functions to convert and save the analyses in
firehose format and to parse the firehose xml files to:
    - label the warnings
    - extract features
    - save trainning set in CSV format
"""

import os
import re
import glob
from collections import defaultdict
from firehose.model import Analysis, CustomFields
from firehose.parsers import frama_c
from firehose.parsers import cppcheck
from firehose.parsers import flawfinder
from firehose.parsers import clanganalyzer


def convert_reports_to_firehose():
    reports = []

    # scan-build (clang analyzer)
    scanbuild_report_results = []
    metadata = None
    for resultdir in glob.glob(os.path.join('reports/scan-build', '*')):
        scanbuild_tmp_firehose_report = clanganalyzer.parse_scandir(resultdir)
        for report in scanbuild_tmp_firehose_report:
            metadata = report.metadata
            scanbuild_report_results += report.results
    scanbuild_firehose_report = Analysis(metadata, scanbuild_report_results)
    reports.append(scanbuild_firehose_report)

    # framac
    with open('reports/frama-c/frama-c.log') as framac_raw_report:
        framac_firehose_report = frama_c.parse_file(framac_raw_report)
        reports.append(framac_firehose_report)

    # flawfinder
    with open('reports/flawfinder/flawfinder.log') as flawfinder_raw_report:
        flawfinder_firehose_report = flawfinder.parse_file(flawfinder_raw_report)
        reports.append(flawfinder_firehose_report)

    # cppcheck
    with open('reports/cppcheck/cppcheck.log') as cppcheck_raw_report:
        cppcheck_firehose_report = cppcheck.parse_file(cppcheck_raw_report)
        reports.append(cppcheck_firehose_report)

    os.makedirs('reports/firehose')
    for report in reports:
        tool_name = report.metadata.generator.name
        fh_report_path = 'reports/firehose/' + tool_name + '.xml'
        with open(fh_report_path, 'wb') as fh_report:
            report.to_xml().write(fh_report, encoding='utf-8')


def get_reports():
    results = []
    for fh_xml_file in glob.glob(os.path.join('reports', 'firehose', '*.xml')):
        results.append(Analysis.from_xml(fh_xml_file))
    return results


def get_line_labels():
    """Return a list to check if a line is contained in a good function, in a
    bad function, or neither, based on Juliet documentation.

    Use the returned list as
    returned_list[file_name_string][line_number_string]. It will return 'bad'
    if the line is in the bad scope of a test case, 'good' if teh line is in
    the good scope of the test case, and the key will not be defined if
    conclusions about the line are not advised by Juliet docs.
    """
    line_labels = {}
    # get cpp classes which may not have the right string in the function names
    with open('cpp_testcases.list', 'r') as cpp_testcases:
        for line in cpp_testcases:
            file_name = os.path.basename(line.split('\n')[0])
            if 'bad' in file_name:
                line_labels[file_name] = defaultdict(lambda: 'bad')
            elif 'good' in file_name:
                line_labels[file_name] = defaultdict(lambda: 'good')

    with open('testcase_functions_scope.list', 'r') as scope_list:
        for line in scope_list:
            absolute_path, function_name, start, end = line.split(':')
            file_name = os.path.basename(absolute_path)
            if file_name not in line_labels:
                line_labels[file_name] = {}
            label = ''
            # what if cpp classes and functions overlap here?
            if 'bad' in function_name:
                label = 'bad'
            elif 'good' in function_name:
                label = 'good'
            else:
                continue  # Discard, as pointed out by Juliet documentation
            for i in range(int(start), int(end) + 1):
                line_labels[file_name][i] = label
    return line_labels


def label_warnings(reports):
    """This function labels each warning as true or false positive. Warnings
    whose label is not possible to determine according to Juliet documentation,
    are removed from the output list.

    in: list with Analysis objects from Juliet analyses
    out: list with Analysis objects labeled as true or false positives.
    """
    line_labels = get_line_labels()
    create_raw_cwe_vs_warning_file = False
    raw_cwe_warning_path = 'raw_cwe_versus_warning_msg.txt'
    raw_cwe_warning_fh = None
    if not os.path.exists(raw_cwe_warning_path):
        """This file is needed to perform the manual extractions of the
        regular expressions used in this function to determine which messages
        correspond to which CWEs. If the file does not exist, create it.
        """
        create_raw_cwe_vs_warning_file = True
        raw_cwe_warning_fh = open(raw_cwe_warning_path, 'w')

    for report in reports:
        # we want to iterate in a copy of results to be able to remove entries.
        for warning in report.results.copy():
            if not warning.location:
                # Only one warning is being discarded here (missing include)
                continue  # discard
            file_name = os.path.basename(warning.location.file.givenpath)
            file_line = warning.location.point.line
            if((not re.search('^CWE[^.]*\.(c|cpp)$', file_name)) or
                    (file_line not in line_labels[file_name])):
                continue  # Discard non labelable warning

            message = warning.message.text
            # cwe = warning.cwe
            # severity = warning.severity
            testcase_cwe = file_name.split('__')[0]
            if create_raw_cwe_vs_warning_file:
                print("%s\t%s" % (testcase_cwe, message), raw_cwe_warning_fh)

            if warning_match_cwe(testcase_cwe, message):
                if warning.customfields is None:
                    warning.customfields = CustomFields()
                if line_labels[file_name][file_line] == 'good':
                    warning.customfields['positive'] = 'true'
                elif line_labels[file_name][file_line] == 'bad':
                    warning.customfields['positive'] = 'false'
            else:
                report.results.remove(warning)

    if raw_cwe_warning_fh is not None:
        raw_cwe_warning_fh.close()
    return reports


def warning_match_cwe(cwe, message):
    regexes = {}
    if cwe == 'CWEZZZ_FOO':
        matching_regex = re.compile('pattern1|pattern2')
    elif cwe == 'CWEZZY_BAR':
        matching_regex = re.compile('pattern1|pattern2')
###############
###############
    elif cwe == 'CWE121_Stack_Based_Buffer_Overflow':
        matching_regex = re.compile(
                'accessing out of bounds index'
                '|Assigned value is garbage or undefined'
                '|Does not check for buffer overflows when (concatenating|copying) to destination'
                '|Easily used incorrectly.*terminate or check for invalid pointers'
                '|Easily used incorrectly.*Consider.*or automatically resizing strings'
                '|out of bounds write'
                '|Size argument is greater than the free space in the destination buffer'
                '|Size argument is greater than the length of the destination buffer'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
                '|String copy function overflows destination buffer'
        )
    elif cwe == 'CWE122_Heap_Based_Buffer_Overflow':
        matching_regex = re.compile(
                'accessing out of bounds index'
                '|Assigned value is garbage or undefined'
                '|Does not check for buffer overflows when (concatenating|copying) to destination'
                '|Easily used incorrectly.*terminate or check for invalid pointers'
                '|Easily used incorrectly.*Consider.*or automatically resizing strings'
                '|out of bounds write'
                '|Size argument is greater than the free space in the destination buffer'
                '|Size argument is greater than the length of the destination buffer'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
                '|String copy function overflows destination buffer'
        )
    elif cwe == 'CWE123_Write_What_Where_Condition':
        matching_regex = re.compile(
                'out of bounds write'
        )
    elif cwe == 'CWE124_Buffer_Underwrite':
        matching_regex = re.compile(
                'Array index -5 is out of bounds'
                '|Assigned value is garbage or undefined'
                '|Does not check for buffer overflows when copying to destination'
                '|Easily used incorrectly.*terminate or check for invalid pointers'
                '|out of bounds write'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
                '|Undefined behaviour, pointer arithmetic.*is out of bounds'
        )
    elif cwe == 'CWE126_Buffer_Overread':
        matching_regex = re.compile(
                'accessing out of bounds index'
                '|Array.*accessed at index.*, which is out of bounds'
                '|Dereference of undefined pointer value'
                '|Does not handle strings that are not.*terminated.*if given one it may perform an over-read'
                '|out of bounds read'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
        )
    elif cwe == 'CWE127_Buffer_Underread':
        matching_regex = re.compile(
                'accessing out of bounds index'
                '|Array index -5 is out of bounds'
                '|Dereference of undefined pointer value'
                '|Does not handle strings that are not.*terminated.*if given one it may perform an over-read'
                '|out of bounds read'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
                '|Undefined behaviour, pointer arithmetic.*is out of bounds'
        )
    elif cwe == 'CWE134_Uncontrolled_Format_String':
        matching_regex = re.compile(
                'If format strings can be influenced by an attacker, they can be exploited.*Use a constant for the format specification'
        )
    elif cwe == 'CWE190_Integer_Overflow':
        matching_regex = re.compile(
                'overflow in conversion from floating-point to integer'
                '|signed overflow'
                '|Unless checked, the resulting number can exceed the expected range'
        )
    elif cwe == 'CWE191_Integer_Underflow':
        matching_regex = re.compile(
                'signed overflow'
                '|Unless checked, the resulting number can exceed the expected range'
        )
        """
CWE194_Unexpected_Sign_Extension    signed overflow.
CWE194_Unexpected_Sign_Extension    Size argument is greater than the length of the destination buffer
CWE194_Unexpected_Sign_Extension    Unless checked, the resulting number can exceed the expected range (CWE-190). If source untrusted, check both minimum and maximum, even if the input had no minus sign (large numbers can roll over into negative number; consider saving to an unsigned value if that is intended).

CWE195_Signed_to_Unsigned_Conversion_Error    signed overflow.
CWE195_Signed_to_Unsigned_Conversion_Error    Size argument is greater than the length of the destination buffer
CWE195_Signed_to_Unsigned_Conversion_Error    Unless checked, the resulting number can exceed the expected range (CWE-190). If source untrusted, check both minimum and maximum, even if the input had no minus sign (large numbers can roll over into negative number; consider saving to an unsigned value if that is intended).


CWE197_Numeric_Truncation_Error    Unless checked, the resulting number can exceed the expected range (CWE-190). If source untrusted, check both minimum and maximum, even if the input had no minus sign (large numbers can roll over into negative number; consider saving to an unsigned value if that is intended).

CWE242_Use_of_Inherently_Dangerous_Function    Obsolete function X called. It is recommended to use X or X instead.

CWE369_Divide_by_Zero    division by zero.
CWE369_Divide_by_Zero    Division by zero
CWE369_Divide_by_Zero    Division by zero.

CWE377_Insecure_Temporary_File    Call to function X is insecure as it always creates or uses insecure temporary file.  Use X instead

CWE398_Poor_Code_Quality    Redundant assignment of X to itself.
CWE398_Poor_Code_Quality    Redundant code: Found a statement that begins with numeric constant.
CWE398_Poor_Code_Quality    Same expression on both sides of X.

CWE401_Memory_Leak    Common realloc mistake: X nulled but not freed upon failure
CWE401_Memory_Leak    Memory leak: X
CWE401_Memory_Leak    Potential leak of memory pointed to by X

CWE415_Double_Free    Attempt to free released memory
CWE415_Double_Free    Deallocating a deallocated pointer: X
CWE415_Double_Free    Memory pointed to by X is freed twice.

CWE416_Use_After_Free    Use of memory after it is freed

CWE440_Expected_Behavior_Violation    Exception thrown in function declared not to throw exceptions.

CWE457_Use_of_Uninitialized_Variable    accessing uninitialized left-value.
CWE457_Use_of_Uninitialized_Variable    Dereference of undefined pointer value
CWE457_Use_of_Uninitialized_Variable    Function call argument is an uninitialized value
CWE457_Use_of_Uninitialized_Variable    Uninitialized variable: X
CWE457_Use_of_Uninitialized_Variable    Variable X is not assigned a value.


CWE467_Use_of_sizeof_on_Pointer_Type    Result of X is converted to a pointer of type X, which is incompatible with sizeof operand type X
CWE467_Use_of_sizeof_on_Pointer_Type    Size of pointer X used instead of size of its data.

CWE469_Use_of_Pointer_Subtraction_to_Determine_Size    pointer subtraction.

CWE476_NULL_Pointer_Dereference    Access to field X results in a dereference of a null pointer (loaded from variable X)
CWE476_NULL_Pointer_Dereference    Array access (from variable X) results in a null pointer dereference
CWE476_NULL_Pointer_Dereference    Dereference of null pointer (loaded from variable X)
CWE476_NULL_Pointer_Dereference    Dereference of undefined pointer value
CWE476_NULL_Pointer_Dereference    Either the condition X is redundant or there is possible null pointer dereference: intPointer.
CWE476_NULL_Pointer_Dereference    Null pointer dereference: X
CWE476_NULL_Pointer_Dereference    Possible null pointer dereference: X

CWE480_Use_of_Incorrect_Operator    Same expression on both sides of X.

CWE481_Assigning_Instead_of_Comparing    Same expression on both sides of X.

CWE526_Info_Exposure_Environment_Variables    Environment variables are untrustable input if they can be set by an attacker. They can have any content and length, and the same variable can be set more than once (CWE-807, CWE-20). Check environment variables carefully before using them.

CWE562_Return_of_Stack_Variable_Address    accessing left-value that contains escaping addresses.

CWE563_Unused_Variable    Unused variable: X
CWE563_Unused_Variable    Value stored to X during its initialization is never read
CWE563_Unused_Variable    Value stored to X is never read
CWE563_Unused_Variable     Variable X is assigned a value that is never used.
CWE563_Unused_Variable    Variable X is reassigned a value before the old one has been used.

CWE570_Expression_Always_False    Checking if unsigned variable X is less than zero.
CWE570_Expression_Always_False    Condition X is always false
CWE570_Expression_Always_False    Unnecessary comparison of static strings.

CWE571_Expression_Always_True    Condition X is always true
CWE571_Expression_Always_True    Same expression on both sides of X.
CWE571_Expression_Always_True    Unnecessary comparison of static strings.
CWE571_Expression_Always_True    Unsigned variable X can't be negative so it is unnecessary to test it.

CWE588_Attempt_to_Access_Child_of_Non_Structure_Pointer    accessing uninitialized left-value.
CWE588_Attempt_to_Access_Child_of_Non_Structure_Pointer    Assigned value is garbage or undefined
CWE588_Attempt_to_Access_Child_of_Non_Structure_Pointer    Dereference of undefined pointer value

CWE590_Free_Memory_Not_on_Heap    Argument to free() is the address of the local variable X, which is not memory allocated by malloc()
CWE590_Free_Memory_Not_on_Heap    Argument to free() is the address of the static variable X, which is not memory allocated by malloc()
CWE590_Free_Memory_Not_on_Heap    Argument to X is the address of the local variable X, which is not memory allocated by X
CWE590_Free_Memory_Not_on_Heap    Argument to X is the address of the static variable X, which is not memory allocated by X
CWE590_Free_Memory_Not_on_Heap    Deallocation of an auto-variable results in undefined behaviour.
CWE590_Free_Memory_Not_on_Heap    Memory allocated by alloca() should not be deallocated

CWE675_Duplicate_Operations_on_Resource    Deallocating a deallocated pointer: X
CWE675_Duplicate_Operations_on_Resource    Resource handle X freed twice.

CWE680_Integer_Overflow_to_Buffer_Overflow    Invalid malloc() argument nr 1. The value is -4 but the valid values are X.
CWE680_Integer_Overflow_to_Buffer_Overflow    Memory allocation size is negative.
CWE680_Integer_Overflow_to_Buffer_Overflow    out of bounds write.
CWE680_Integer_Overflow_to_Buffer_Overflow    signed overflow.
CWE680_Integer_Overflow_to_Buffer_Overflow    Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues (CWE-119:CWE-120). Perform bounds checking, use functions that limit length, or ensure that the size is larger than the maximum possible length.
CWE680_Integer_Overflow_to_Buffer_Overflow    Suspicious code: sign conversion of data in calculation, even though data can have a negative value
CWE680_Integer_Overflow_to_Buffer_Overflow    Unless checked, the resulting number can exceed the expected range (CWE-190). If source untrusted, check both minimum and maximum, even if the input had no minus sign (large numbers can roll over into negative number; consider saving to an unsigned value if that is intended).

CWE681_Incorrect_Conversion_Between_Numeric_Types    overflow in conversion from floating-point to integer.

CWE685_Function_Call_With_Incorrect_Number_of_Arguments    sprintf format string requires 2 parameters but only 1 is given.

CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument    %s in format string (no. 1) requires X but the argument type is X.

CWE761_Free_Pointer_Not_at_Start_of_Buffer    Argument to free() is offset by X byte from the start of memory allocated by malloc()
CWE761_Free_Pointer_Not_at_Start_of_Buffer    Argument to free() is offset by X bytes from the start of memory allocated by malloc()

CWE762_Mismatched_Memory_Management_Routines    Memory allocated by calloc() should be deallocated by free(), not X
CWE762_Mismatched_Memory_Management_Routines    Memory allocated by malloc() should be deallocated by free(), not X
CWE762_Mismatched_Memory_Management_Routines    Memory allocated by realloc() should be deallocated by free(), not X
CWE762_Mismatched_Memory_Management_Routines    Memory allocated by strdup() should be deallocated by free(), not X
CWE762_Mismatched_Memory_Management_Routines    Memory allocated by X should be deallocated by X, not free()
CWE762_Mismatched_Memory_Management_Routines    Memory allocated by X should be deallocated by X, not X
CWE762_Mismatched_Memory_Management_Routines    Mismatching allocation and deallocation: X

CWE775_Missing_Release_of_File_Descriptor_or_Handle    Resource leak: X
        """

###############
###############

    return re.search(matching_regex, message)


if __name__ == "__main__":
    # check if reports are already converted
    # if not, convert them
    if not os.path.exists('reports/firehose'):
        convert_reports_to_firehose()

    if not os.path.exists('reports/firehose/labeled_reports'):
        reports = get_reports()
        labeled_reports = label_warnings(reports)
        for report in labeled_reports:
            tool_name = report.metadata.generator.name
            fh_report_path = 'reports/firehose/labeled_reports' + tool_name + '.xml'
            with open(fh_report_path, 'wb') as fh_report:
                report.to_xml().write(fh_report, encoding='utf-8')
