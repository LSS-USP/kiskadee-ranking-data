#!/bin/bash

# Note that the first line poits to the function signature and the last line 1st char is the end of the function
# So a warning in the last line of FUNCTION_DEFINITION is not pointing to the function itself (always use less than)

OUTPUT_FILE=testcase_functions_scope.list
FUNCTION_REGEX="[Gg]ood|[Bb]ad"

rm -f $OUTPUT_FILE

for FILENAME in `cat c_testcases.list cpp_testcases.list`; do
  for PARTIAL in `ctags -x --c-kinds=f $FILENAME | grep ' function ' | awk '{ print $1 ":" $3 }'`; do
    if [[ $PARTIAL =~ $FUNCTION_REGEX ]]; then
      FIRST_LINE=`echo $PARTIAL | cut -d ':' -f2`
      # heuristics here is that if a line starts with }, it is the end of a function
      LAST_LINE=`awk 'NR > first && /^}/ { print NR; exit }' first=$FIRST_LINE $FILENAME`
      FUNCTION_DEFINITION=${FILENAME}:${PARTIAL}:$LAST_LINE
      echo $FUNCTION_DEFINITION >> $OUTPUT_FILE
    fi
  done
done
