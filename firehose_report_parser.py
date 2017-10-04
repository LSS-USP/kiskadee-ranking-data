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
from firehose.model import Analysis
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
        scanbuild_partial_firehose_report = clanganalyzer.parse_scandir(resultdir)
        for report in scanbuild_partial_firehose_report:
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


def label_reports(reports):
    """This function labels each warning as true or false positive. Warnings
    whose label is not possible to determine according to Juliet documentation,
    are removed from the output list.

    in: list with Analysis objects from Juliet analyses
    out: list with Analysis objects labeled as true or false positives.
    """
    # TODO: Label warnings coming from classes here
    line_labels = get_line_labels()
    for report in reports:
        for warning in report.results:
            if not warning.location:
                # print(warning)
                continue # discard. TODO: verify what is being lost here
            file_name = os.path.basename(warning.location.file.givenpath)
            file_line = warning.location.point.line
            if (not re.search('^CWE[^.]*\.(c|cpp)$', file_name)) or (file_line not in line_labels[file_name]):
                continue  # Discard non labelable warning

            message = warning.message.text
            # cwe = warning.cwe
            # severity = warning.severity

            testcase_cwe = file_name.split('__')[0]
            print("%s\t%s" % (testcase_cwe, message))


if __name__ == "__main__":
    # check if reports are already converted
    # if not, convert them
    if not os.path.exists('reports/firehose'):
        convert_reports_to_firehose()

    reports = get_reports()
    label_reports(reports)
