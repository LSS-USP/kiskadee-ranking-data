library(caret)
print("LOG: BEGIN")
raw_data <- read.csv("features.csv", header=TRUE, sep=",")

inTraining <- createDataPartition(raw_data$label, p = .75, list = FALSE)
training_data <- raw_data[ inTraining,]
testing_data  <- raw_data[-inTraining,]

train_control <- trainControl(method="repeatedcv", number=10, repeats=10)
# grid <- expand.grid(nIter=10, method='Adaboost.M1')
set.seed(825)
model <- train(label~tool_name+severity+redundancy_level+neighbors+category+clang_analyzer+frama_c+cppcheck+warnings_in_this_file+language, data=training_data, trControl=train_control, method="adaboost") #, tuneGrid=grid)
print("LOG: Model")
model


modelImp <- varImp(model, scale = FALSE)
modelImp
ggplot(modelImp)

predictions = predict(model, newdata = testing_data)
probabilities = predict(model, newdata = testing_data, type="prob")

confusion_matrix = confusionMatrix(predictions, testing_data$label, positive="true", mode="prec_recall")

print("LOG: Predictions")
predictions
print("LOG: Labels")
testing_data$label
print("LOG: Probabilities")
probabilities
print("LOG: Confusion Matrix")
confusion_matrix

print("LOG: Plotting...")
ggplot(model)
print("LOG: Saving...")
save.image()
print("LOG: END, model saved at .RData")
