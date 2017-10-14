import csv
from sklearn import preprocessing
from sklearn import tree, ensemble
from sklearn.metrics import accuracy_score
from sklearn.model_selection import train_test_split

tools = ['clang-analyzer', 'cppcheck', 'flawfinder', 'frama-c']
categories = ['buffer', 'div0', 'memory', 'other', 'overflow', 'pointer']
le_tools = preprocessing.LabelEncoder()
le_categories = preprocessing.LabelEncoder()

X = []
Y = []

with open('features.csv', 'r') as features_csv:
    headers = features_csv.readline()
    for line in features_csv:
        line = line.split('\n')[0]
        # X.append(line.split(',')[1:-1])
        line = line.split(',')
        features = line[2:-2]
        features[0] = int(features[0])
        features[1] = int(features[1])
        features[2] = int(features[2])
        X.append(features)
        if line[-1] == 'true':
            Y.append(1)
        elif line[-1] == 'false':
            Y.append(-1)
        else:
            print(line)
            print("[%s]" % line[-1])
            print('missing value')
            exit(1)

X_train, X_test, Y_train, Y_test = train_test_split(X, Y, random_state=None)
model = tree.DecisionTreeClassifier()
# model = ensemble.AdaBoostClassifier(n_estimators=100)
# model = model.fit(X_train, Y_train)

# Y_predict = model.predict(X_test)

# print(accuracy_score(Y_test, Y_predict))
