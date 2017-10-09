"""
Use this same file to aggregate functions to convert and save the analyses in
firehose format and to parse the firehose xml files to:
    - label the warnings
    - extract features
    - save trainning set in CSV format

python firehose_report_parser.py
    Convert reports to firehose format and label them

python firehose_report_parser.py stats
    Prints stats related to the reports
"""

import os
import re
import sys
import csv
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

def get_labeled_reports():
    results = []
    for fh_xml_file in glob.glob(os.path.join('reports', 'firehose', 'labeled_reports', '*.xml')):
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
                # Discard non labelable warning (missing include warnings)
                report.results.remove(warning)
                continue  # discard
            file_name = os.path.basename(warning.location.file.givenpath)
            file_line = warning.location.point.line
            if((not re.search('^CWE[^.]*\.(c|cpp)$', file_name)) or
                    (file_line not in line_labels[file_name])):
                # Discard non labelable warning
                report.results.remove(warning)
                continue

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
                    raise NameError("Cannot label warning")
            else:
                report.results.remove(warning)

    if raw_cwe_warning_fh is not None:
        raw_cwe_warning_fh.close()
    return reports


def warning_match_cwe(cwe, message):
    matching_regex = None
    if cwe == 'CWE121_Stack_Based_Buffer_Overflow':
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
                'Array index.*is out of bounds'
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
                '|Array index.*is out of bounds'
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
    elif cwe == 'CWE194_Unexpected_Sign_Extension':
        matching_regex = re.compile(
                'signed overflow'
                '|Size argument is greater than the length of the destination buffer'
                '|Unless checked, the resulting number can exceed the expected range'
        )
    elif cwe == 'CWE195_Signed_to_Unsigned_Conversion_Error':
        matching_regex = re.compile(
                'signed overflow'
                '|Size argument is greater than the length of the destination buffer'
                '|Unless checked, the resulting number can exceed the expected range'
        )
    elif cwe == 'CWE197_Numeric_Truncation_Error':
        matching_regex = re.compile(
                'Unless checked, the resulting number can exceed the expected range'
        )
    elif cwe == 'CWE242_Use_of_Inherently_Dangerous_Function':
        matching_regex = re.compile(
                'Obsolete function.*called\. It is recommended to use.*or.*instead'
        )
    elif cwe == 'CWE369_Divide_by_Zero':
        matching_regex = re.compile(
                '[dD]ivision by zero'
        )
    elif cwe == 'CWE377_Insecure_Temporary_File':
        matching_regex = re.compile(
                'is insecure as it always creates or uses insecure temporary file'
        )
    elif cwe == 'CWE398_Poor_Code_Quality':
        matching_regex = re.compile(
                'Redundant assignment of.*to itself'
                '|Redundant code: Found a statement that begins with numeric constant'
                '|Same expression on both sides of'
        )
    elif cwe == 'CWE401_Memory_Leak':
        matching_regex = re.compile(
                'Common realloc mistake.*nulled but not freed upon failure'
                '|Memory leak'
                '|Potential leak of memory pointed to by'
        )
    elif cwe == 'CWE415_Double_Free':
        matching_regex = re.compile(
                'Attempt to free released memory'
                '|Deallocating a deallocated pointer'
                '|Memory pointed to by.*is freed twice'
        )
    elif cwe == 'CWE416_Use_After_Free':
        matching_regex = re.compile(
                'Use of memory after it is freed'
        )
    elif cwe == 'CWE440_Expected_Behavior_Violation':
        matching_regex = re.compile(
                'Exception thrown in function declared not to throw exceptions'
        )
    elif cwe == 'CWE457_Use_of_Uninitialized_Variable':
        matching_regex = re.compile(
                'accessing uninitialized left-value'
                '|Dereference of undefined pointer value'
                '|Function call argument is an uninitialized value'
                '|Uninitialized variable'
                '|Variable.*is not assigned a value'
        )
    elif cwe == 'CWE467_Use_of_sizeof_on_Pointer_Type':
        matching_regex = re.compile(
                'Result of.*is converted to a pointer of type.*which is incompatible with sizeof operand type'
                '|Size of pointer.*used instead of size of its data'
        )
    elif cwe == 'CWE469_Use_of_Pointer_Subtraction_to_Determine_Size':
        matching_regex = re.compile(
                'pointer subtraction'
        )
    elif cwe == 'CWE476_NULL_Pointer_Dereference':
        matching_regex = re.compile(
                'Access to field.*results in a dereference of a null pointer'
                '|Array access.*results in a null pointer dereference'
                '|Dereference of null pointer'
                '|Dereference of undefined pointer value'
                '|Either the condition.*is redundant or there is possible null pointer dereference'
                '|Null pointer dereference'
                '|Possible null pointer dereference'
        )
    elif cwe == 'CWE480_Use_of_Incorrect_Operator':
        matching_regex = re.compile(
                'Same expression on both sides of'
        )
    elif cwe == 'CWE481_Assigning_Instead_of_Comparing':
        matching_regex = re.compile(
                'Same expression on both sides of'
        )
    elif cwe == 'CWE526_Info_Exposure_Environment_Variables':
        matching_regex = re.compile(
                'Environment variables are untrustable input if they can be set by an attacker'
        )
    elif cwe == 'CWE562_Return_of_Stack_Variable_Address':
        matching_regex = re.compile(
                'accessing left-value that contains escaping addresses'
        )
    elif cwe == 'CWE563_Unused_Variable':
        matching_regex = re.compile(
                'Unused variable'
                '|Value stored to.*during its initialization is never read'
                '|Value stored to.*is never read'
                '|Variable.*is assigned a value that is never used'
                '|Variable.*is reassigned a value before the old one has been used'
        )
    elif cwe == 'CWE570_Expression_Always_False':
        matching_regex = re.compile(
                'Checking if unsigned variable.*is less than zero'
                '|Condition.*is always false'
                '|Unnecessary comparison of static strings'
        )
    elif cwe == 'CWE571_Expression_Always_True':
        matching_regex = re.compile(
                'Condition.*is always true'
                '|Same expression on both sides of'
                '|Unnecessary comparison of static strings'
                '|Unsigned variable.*can.t be negative so it is unnecessary to test it'
        )
    elif cwe == 'CWE588_Attempt_to_Access_Child_of_Non_Structure_Pointer':
        matching_regex = re.compile(
                'accessing uninitialized left-value'
                '|Assigned value is garbage or undefined'
                '|Dereference of undefined pointer value'
        )
    elif cwe == 'CWE590_Free_Memory_Not_on_Heap':
        matching_regex = re.compile(
                'Argument to.*is the address of the.*variable.*which is not memory allocated by'
                '|Deallocation of an auto-variable results in undefined behaviour'
                '|Memory allocated by.*should not be deallocated'
        )
    elif cwe == 'CWE675_Duplicate_Operations_on_Resource':
        matching_regex = re.compile(
                'Deallocating a deallocated pointer'
                '|Resource handle.*freed twice'
        )
    elif cwe == 'CWE680_Integer_Overflow_to_Buffer_Overflow':
        matching_regex = re.compile(
                'Invalid malloc.. argument.*The value is.*but the valid values are'
                '|Memory allocation size is negative'
                '|out of bounds write'
                '|signed overflow'
                '|Statically-sized arrays can be improperly restricted, leading to potential overflows or other issues'
                '|Suspicious code: sign conversion of data in calculation, even though data can have a negative value'
                '|Unless checked, the resulting number can exceed the expected range'
        )
    elif cwe == 'CWE681_Incorrect_Conversion_Between_Numeric_Types':
        matching_regex = re.compile(
                'overflow in conversion from floating-point to integer'
        )
    elif cwe == 'CWE685_Function_Call_With_Incorrect_Number_of_Arguments':
        matching_regex = re.compile(
                'format string requires.*parameters but only.*is given'
        )
    elif cwe == 'CWE688_Function_Call_With_Incorrect_Variable_or_Reference_as_Argument':
        matching_regex = re.compile(
                'in format string.*requires.*but the argument type is'
        )
    elif cwe == 'CWE761_Free_Pointer_Not_at_Start_of_Buffer':
        matching_regex = re.compile(
                'Argument to free.. is offset by X byte.* from the start of memory allocated by'
        )
    elif cwe == 'CWE762_Mismatched_Memory_Management_Routines':
        matching_regex = re.compile(
                'Memory allocated by.*should be deallocated by.*, not'
                '|Mismatching allocation and deallocation'
        )
    elif cwe == 'CWE775_Missing_Release_of_File_Descriptor_or_Handle':
        matching_regex = re.compile(
                'Resource leak'
        )

    if matching_regex is not None:
        return re.search(matching_regex, message)
    else:
        return None


def print_stats(reports, header, labels=False):
    total_warnings = 0
    print('%s:' % header)
    for report in reports:
        tool = report.metadata.generator.name
        warnings = len(report.results)
        total_warnings += warnings
        print('\t%s: %s' % (tool, warnings))
        if labels:
            tp = 0  # true positives
            fp = 0  # false positives
            for warning in report.results:
                if warning.customfields['positive'] == 'true':
                    tp += 1
                else:
                    fp += 1
            print('\t\tTP: %s' % tp)
            print('\t\tFP: %s' % fp)
    print('\tTOTAL: %s' % total_warnings)


def extract_features(labeled_reports):
    """
    input: labeled reports
    output: features CSV file
    """
    features_csv = open('features.csv', 'w', newline='')
    feature_writer = csv.writer(features_csv)
    feature_writer.writerow(['location', 'tool_name', 'severity', 'redundancy_level', 'neighbors', 'category', 'label'])
    for report in labeled_reports:
        for warning in report.results:
            warning.customfields['redundancy_level'] = 0
            warning.customfields['neighbors'] = 0
            label = warning.customfields['positive']
            tool_name = report.metadata.generator.name
            file_name = os.path.basename(warning.location.file.givenpath)
            file_line = warning.location.point.line
            severity = warning.severity
            for other in report.results:
                other_file_name = os.path.basename(other.location.file.givenpath)
                other_file_line = other.location.point.line
                if(file_name == other_file_name):
                    if(file_line == other_file_line):
                        warning.customfields['redundancy_level'] += 1
                    elif(int(file_line) - 2 <= int(other_file_line) <= int(file_line) + 2):
                        warning.customfields['neighbors'] += 1

            if(re.search('^CWE12\d|^CWE680', file_name)):
                warning.customfields['category'] = 'buffer'
            elif(re.search('^CWE19\d', file_name)):
                warning.customfields['category'] = 'overflow'
            elif(re.search('^CWE369', file_name)):
                warning.customfields['category'] = 'div0'
            elif(re.search('^CWE4(67|69|76)', file_name)):
                warning.customfields['category'] = 'pointer'
            elif(re.search('^CWE(401|415|416|562|590|675|761|762)', file_name)):
                warning.customfields['category'] = 'memory'
            else:
                warning.customfields['category'] = 'other'

            redundancy_level = warning.customfields['redundancy_level']
            neighbors = warning.customfields['neighbors']
            category = warning.customfields['category']
            location = file_name + ':' + file_line
            if severity is None:
                severity = 3
            elif severity == 'error':
                severity = 5
            elif severity == 'warning':
                severity = 4
            elif severity == 'style':
                severity = 3
            elif severity == 'performance':
                severity = 2
            elif severity == 'portability':
                severity = 1
            elif severity == 'debug':
                severity = 0
            elif severity == 'information':
                severity = 0
            feature_writer.writerow([location, tool_name, severity, redundancy_level, neighbors, category, label])
            # print("%s:%s,%s,%s,%s,%s,%s,%s" % (file_name, file_line, tool_name, severity, redundancy_level, neighbors, category, label))
    features_csv.close()


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == 'features':
        print('extracting...')
        labeled_reports = get_labeled_reports()
        extract_features(labeled_reports)
        sys.exit(0)

    if len(sys.argv) > 1 and sys.argv[1] == 'stats':
        if not os.path.exists('reports/firehose/labeled_reports'):
            sys.exit(1)
        reports = get_reports()
        labeled_reports = get_labeled_reports()
        print_stats(reports, "Number of warnings triggered")
        print()
        print_stats(labeled_reports, "Number of warnings labeled", True)
        sys.exit(0)

    # if reports are not converted to firehose yet, convert
    if not os.path.exists('reports/firehose'):
        convert_reports_to_firehose()

    # if reports are not labeled yet, label
    if not os.path.exists('reports/firehose/labeled_reports'):
        os.makedirs('reports/firehose/labeled_reports')
        reports = get_reports()
        labeled_reports = label_warnings(reports)
        for report in labeled_reports:
            tool_name = report.metadata.generator.name
            fh_report_path = 'reports/firehose/labeled_reports/' + tool_name + '.xml'
            with open(fh_report_path, 'wb') as fh_report:
                report.to_xml().write(fh_report, encoding='utf-8')
