from firehose.parsers import clanganalyzer
from firehose.parsers import frama_c
from firehose.parsers import flawfinder
from firehose.parsers import cppcheck
from firehose.model import Analysis
import xml.etree.ElementTree as ET
import json

# scan-build (clang analyzer)
# clanganalyzer_report = 'reports/scan-build/2017-09-27-212739-17278-1/report-zyCXmC.plist'
# fh_clanganalyzer_report = clanganalyzer.parse_plist(clanganalyzer_report)
# print(len(fh_clanganalyzer_report.results))

clanganalyzer_report = 'reports/scan-build/2017-09-27-212739-17278-1'
fh_clanganalyzer_report = clanganalyzer.parse_scandir(clanganalyzer_report)

all_clang_results = []
metadata = None
for a in fh_clanganalyzer_report:
    metadata = a.metadata
    # print(len(a.results))
    # print(a.metadata)
    all_clang_results += a.results
# print(a.results[0])
# print(type(a.results[0]))
print(len(all_clang_results))
clang_merged_analyses = Analysis(metadata, all_clang_results)
# print(clang_merged_analyses.results)
print(len(clang_merged_analyses.results))

# framac
with open('reports/frama-c/frama-c.log') as framac_report:
    fh_framac_report = frama_c.parse_file(framac_report)
    print(len(fh_framac_report.results))

# flawfinder
with open('reports/flawfinder/flawfinder.log') as flawfinder_report:
    fh_flawfinder_report = flawfinder.parse_file(flawfinder_report)
    print(len(fh_flawfinder_report.results))

# cppcheck
with open('reports/cppckeck/cppckeck.log') as cppckeck_report:
    fh_cppckeck_report = cppcheck.parse_file(cppckeck_report)
    print(len(fh_cppckeck_report.results))
