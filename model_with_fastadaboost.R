#location,tool_name,severity,redundancy_level,neighbors,category,clang-analyzer,frama-c,cppcheck,flawfinder,label
library(fastAdaboost)
raw_data <- read.csv("features.csv", header=TRUE, sep=",")
print("begin training M1")
test_adaboost<-adaboost(label~tool_name+severity+redundancy_level+neighbors+category+clang_analyzer+frama_c+cppcheck+warnings_in_this_file+language, raw_data, 20)
print("end training")
print("begin predictions M1")
pred <- predict( test_adaboost,newdata=raw_data)
print("end predictions")
print("printing adaboost M1")
print(test_adaboost)
print("end printing adaboost")
print("ERROR M1:")
print(pred$error)
#print("VOTES M1:")
#print(pred$votes)
#print("VOTES CLASS:")
#print(pred$class)
#print("VOTES FORMULA:")
#print(pred$formula)
#print("VOTES PROB:")
#print(pred$prob)
#print("END")


#print("begin training SAMMER.R")
#test_real_adaboost<-real_adaboost(label~tool_name+severity+redundancy_level+neighbors+category+clang_analyzer+frama_c+cppcheck+warnings_in_this_file+language, raw_data, 10)
#print("end training")
#print("begin predictions SAMMER.R")
#pred_real <- predict( test_real_adaboost,newdata=raw_data)
#print("end predictions")
#print("printing adaboost SAMMER.R")
#print(test_real_adaboost)
#print("end printing adaboost")
#print("ERROR SAMMER.R:")
#print(pred_real$error)
#print("END")
