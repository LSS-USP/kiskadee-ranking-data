library(adabag)
print("imported")
raw_data <- read.csv("features.csv", header=TRUE, sep=",")
print("loaded file")
# raw_data
# location,tool_name,severity,redundancy_level,neighbors,category,label
adaboost<-boosting(label~tool_name+severity+redundancy_level+neighbors+category, data=raw_data, boos=TRUE, mfinal=20,coeflearn='Breiman')
print("trained data")
summary(adaboost)
adaboost$trees
adaboost$weights
adaboost$importance
errorevol(adaboost,raw_data)
predict(adaboost,raw_data)
t1<-adaboost$trees[[1]]
library(tree)
plot(t1)
text(t1,pretty=0)
print("END")
