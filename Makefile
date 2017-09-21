analysis: bootstrap
	./run_analysis.sh

c_testcases.list cpp_testcases.list juliet: bootstrap.sh
	./bootstrap.sh

bootstrap: c_testcases.list cpp_testcases.list juliet

.PHONY: clean analysis bootstrap

clean:
	rm -rf juliet *.list reports *.zip
