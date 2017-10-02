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

    # print(reports[0].results[0].location.file.givenpath)
    # print(reports[0].results[0].location.point.line)
    os.makedirs('reports/firehose')
    for report in reports:
        tool_name = report.metadata.generator.name
        fh_report_path = 'reports/firehose/' + tool_name + '.xml'
        with open(fh_report_path, 'w') as fh_report:
            fh_report.write(str(report.to_xml()))
        # print(len(report.results))


if __name__ == "__main__":
    # check if reports are already converted
    # if not, convert them
    if not os.path.exists('reports/firehose'):
        convert_reports_to_firehose()
