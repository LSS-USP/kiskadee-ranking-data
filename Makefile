all: analysis funcinfo label stats features

analysis: bootstrap
	./run_analyses.sh

c_testcases.list cpp_testcases.list juliet: bootstrap.sh
	./bootstrap.sh

bootstrap: c_testcases.list cpp_testcases.list juliet

testcase_functions_scope.list: get_functions_info.sh
	./get_functions_info.sh

funcinfo: testcase_functions_scope.list

label: bootstrap analysis funcinfo
	python firehose_report_parser.py

# All data files should be dependencieas here
experiment_numbers.report: collect_data.sh firehose_report_parser.py reports/firehose
	./collect_data.sh > experiment_numbers.report

stats: experiment_numbers.report label

features.csv:
	python firehose_report_parser.py features

features: features.csv label

.PHONY: clean analysis bootstrap funcinfo all stats features

clean:
	rm -rf juliet *.list reports *.zip experiment_numbers.report features.csv
