library(caret)
raw_data <- read.csv("features.csv", header=TRUE, sep=",")

inTraining <- createDataPartition(raw_data$label, p = .75, list = FALSE)
training_data <- raw_data[ inTraining,]
testing_data  <- raw_data[-inTraining,]

train_control <- trainControl(method="cv", number=10, repeats=10)
# grid <- expand.grid(nIter=10, method='Adaboost.M1')
set.seed(825)
model <- train(label~tool_name+severity+redundancy_level+neighbors+category+clang_analyzer+frama_c+cppcheck+warnings_in_this_file, data=training_data, trControl=train_control, method="adaboost")#, tuneGrid=grid)
print(model)


modelImp <- varImp(model, scale = FALSE)
print(modelImp)
ggplot(modelImp)

predict(model, newdata = testing_data)
predict(model, newdata = testing_data, type="prob")
ggplot(model)
