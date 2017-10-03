"""
Use this same file to aggregate functions to convert and save the analyses in
firehose format and to parse the firehose xml files to:
    - label the warnings
    - extract features
    - save trainning set in CSV format
"""

import os
import glob
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


# TODO: rename this function and returning list.
def get_function_scopes():
    function_scopes = {}
    with open('testcase_functions_scope.list', 'r') as scope_list:
        for line in scope_list:
            absolute_path, function_name, start, end = line.split(':')
            file_name = os.path.basename(absolute_path)
            if file_name not in function_scopes:
                function_scopes[file_name] = {}
            label = ''
            # what if cpp classes and functions overlap here?
            if 'bad.cpp' in file_name:
                label = 'bad'
            elif 'good.cpp' in file_name:
                label = 'good'
            elif 'bad' in function_name:
                label = 'bad'
            elif 'good' in function_name:
                label = 'good'
            else:
                # we do not want to check warnings in other functions
                # as pointed out by Juliet's documentation
                continue
            for i in range(start, end + 1):
                function_scopes[file_name][i] = label
    return function_scopes


def label_reports(reports):
    """
    This function labels each warning as true or false positive. Warnings whose
    label is not possible to determine according to Juliet documentation, are
    removed from the output list

    in: list with Analysis objects from Juliet analyses
    out: list with Analysis objects labeled as true or false positives.
    """
    # TODO: create hash with filenames, containing each function name, start and end.
    # maybe we could have sth like: function['CWEZZZ_foo_01.c'][34] = 'function_name'
    # this could be achieved with a loop for each line of the function names file
    # where it just write the name of each functions in the right list's specifit indexes
    for report in reports:
        for warning in report.results:
            file_name = warning.location.file.givenpath
            file_line = warning.location.point.line
            message = warning.message.text
            cwe = warning.cwe
            severity = warning.severity


if __name__ == "__main__":
    # check if reports are already converted
    # if not, convert them
    if not os.path.exists('reports/firehose'):
        convert_reports_to_firehose()

    reports = get_reports()
    label_reports(reports)
