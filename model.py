
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from time import sleep, time
from random import randint
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from pynput import keyboard


df = pd.read_csv("./data.csv")


maps = []
for feat in ["protocol_type", "service", "flag", "class"]:
  map = {}
  for i in range(len(list(df[feat].unique()))):
    val = list(df[feat].unique())[i]
    map[val] = i
  df[feat].replace(map, inplace=True)
  print(map)

for feat in list(df.columns):
  for val in list(df[feat].unique()):
    map = {}
    try:
      if type(val) != int:
        map = {val: int(val)}
        map = {val: float(val)}
    except :
      map = {val: 0.0}
    df[feat].replace(map, inplace=True)

df["same_srv_rate"].fillna(0)


# First zip the columns of the dataset and split into data and labels
cols = [list(df[col]) for col in df.columns]
zipped = list(zip(*cols))
X = [row[:-1] for row in zipped]
y = [row[-1] for row in zipped]

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.33, random_state=42)

forest = RandomForestClassifier();

# fit random forest classifier on the training set
forest.fit(X_train, y_train);
# extract important features
score = np.round(forest.feature_importances_,3)
importances_dict = {'feature':list(df.columns[:-1]),'importance':score}
importances = pd.DataFrame({'feature':list(df.columns[:-1]),'importance':score})
importances = importances.sort_values('importance',ascending=False).set_index('feature')
# plot importances
# plt.rcParams['figure.figsize'] = (11, 4)
# importances.plot.bar();

arr = []
for i in range(len(importances_dict["importance"])):
  if importances_dict["importance"][i]>0.04:
    arr.append([importances_dict['feature'][i], importances_dict["importance"][i]])

print(arr)

post_selected = []
for i in arr:
  post_selected.append(i[0])
print(post_selected)


cols = [list(df[col]) for col in post_selected + ["class"]]
zipped = list(zip(*cols))
X = [row[:-1] for row in zipped]
y = [row[-1] for row in zipped]

from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.40, random_state=42)


from sklearn.tree import DecisionTreeClassifier
clf = DecisionTreeClassifier(random_state=67,min_samples_leaf=10,min_samples_split=5,max_depth=10,max_leaf_nodes=10)
clf.fit(X_train, y_train)
clf.score(X_test, y_test)



# @title Classification Pruning
print("Attack Indices:\n{'normal': 0, 'buffer_overflow': 1, 'loadmodule': 2, 'perl': 3, 'neptune': 4, 'smurf': 5,\n 'guess_passwd': 6, 'pod': 7, 'teardrop': 8, 'portsweep': 9, 'ipsweep': 10, 'land': 11, 'ftp_write': 12, 'back': 13,\n 'imap': 14, 'satan': 15, 'phf': 16, 'nmap': 17, 'multihop': 18,\n 'warezmaster': 19, 'warezclient': 20, 'spy': 21, 'rootkit': 22}")
pd.Series(y_test).value_counts()


y_pred = clf.predict(X_test)


df2 = df.copy()
df2.drop(columns=['srv_count','dst_host_same_src_port_rate','src_bytes','count', 'protocol_type'])


cols2 = [list(df2[col]) for col in df2.columns]
zipped2 = list(zip(*cols2))
X2 = [row[:-1] for row in zipped2]
y2 = [row[-1] for row in zipped2]

X2_train, X2_test, y2_train, y2_test = train_test_split(X2, y2, test_size=0.33, random_state=42)


clf2 = DecisionTreeClassifier(random_state=67,min_samples_leaf=10,min_samples_split=5,max_depth=10,max_leaf_nodes=10)
clf2.fit(X2_train, y2_train)
clf2.score(X2_test, y2_test)

send_anomaly = False

def on_press(key):
    global send_anomaly
    send_anomaly = True


def on_release(key):
    pass

listener = keyboard.Listener(
    on_press=on_press,
    on_release=on_release)
listener.start()


start_time = time()
normals = []
abnormals = []
for i in range(len(X)):
    if y[i] == 0:
        normals.append(X[i])
    else:
        abnormals.append(X[i])

#anomaly count
while True:
    attack_num = randint(0, 2000)
    pred = int(clf.predict(np.array(normals[attack_num]).reshape(1, -1))[0])
    if send_anomaly:
        attack_num = randint(0, len(abnormals))
        pred = int(clf.predict(np.array(abnormals[attack_num]).reshape(1, -1))[0])
        # start_time = time()
        send_anomaly = False

    if int(pred) != 0:
        print("Intrusion Detected!!!!")


