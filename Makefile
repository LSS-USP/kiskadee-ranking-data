all: analysis funcinfo

analysis: bootstrap
	./run_analyses.sh

c_testcases.list cpp_testcases.list juliet: bootstrap.sh
	./bootstrap.sh

bootstrap: c_testcases.list cpp_testcases.list juliet

testcase_functions_scope.list: get_functions_info.sh
	./get_functions_info.sh

funcinfo: testcase_functions_scope.list

.PHONY: clean analysis bootstrap funcinfo all

clean:
	rm -rf juliet *.list reports *.zip
