library(caret)
raw_data <- read.csv("features.csv", header=TRUE, sep=",")
train_control <- trainControl(method="cv", number=10)
# ??
# grid <- expand.grid(.fL=c(0), .usekernel=c(FALSE))
#grid <- expand.grid(nIter=5, method='')
#model <- train(label~tool_name+severity+redundancy_level+neighbors+category, data=raw_data, trControl=train_control, method="nb", tuneGrid=grid)
# adaboost uses the fastadaboostpackage
# the nIter param sets the number of trees to train
#model <- train(label~tool_name+severity+redundancy_level+neighbors+category, data=raw_data, trControl=train_control, method="adaboost", tuneGrid=grid)
model <- train(label~tool_name+severity+redundancy_level+neighbors+category, data=raw_data, trControl=train_control, method="adaboost")
print(model)
