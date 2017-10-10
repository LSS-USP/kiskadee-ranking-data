all: analysis funcinfo label stats features

analysis: reports run_analyses.sh

run_analyses.sh reports: bootstrap 
	./run_analyses.sh

c_testcases.list cpp_testcases.list juliet: bootstrap.sh
	./bootstrap.sh

bootstrap: c_testcases.list cpp_testcases.list juliet

testcase_functions_scope.list: get_functions_info.sh bootstrap
	./get_functions_info.sh

funcinfo: testcase_functions_scope.list

label: bootstrap analysis funcinfo firehose_report_parser.py

firehose_report_parser.py: reports/firehose reports/firehose/labeled_reports

reports/firehose reports/firehose/labeled_reports:
	python firehose_report_parser.py

# All data files should be dependencieas here
experiment_numbers.report: collect_data.sh label
	./collect_data.sh > experiment_numbers.report

stats: experiment_numbers.report

features.csv: label
	python firehose_report_parser.py features

features: features.csv

.PHONY: clean analysis bootstrap funcinfo all stats features label

clean:
	rm -rf juliet *.list reports *.zip experiment_numbers.report features.csv
