from firehose.parsers import clanganalyzer
from firehose.parsers import frama_c
from firehose.parsers import flawfinder
from firehose.parsers import cppcheck
from firehose.model import Analysis
import glob
import os
# import xml.etree.ElementTree as ET
# import json

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

print(reports[0].results[0].location.file.givenpath)
print(reports[0].results[0].location.point.line)
print(reports[1].results[0].location.file.givenpath)
print(reports[1].results[0].location.point.line)
print(reports[2].results[0].location.file.givenpath)
print(reports[2].results[0].location.point.line)
print(reports[3].results[0].location.file.givenpath)
print(reports[3].results[0].location.point.line)
for report in reports:
    print(len(report.results))
