"""_summary_
Using Random Forest for Defect Prediction
"""
import pandas as pd
import csv
from adapt.feature_based import CORAL
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import KFold
from sklearn.metrics import classification_report
import joblib
PROJECTS = ['mjs']
for PROJECT in PROJECTS:
    DATA_PATH = r'/home/a/fuzz/DPfuzz/script/py/prediction/nasaData/MDP.csv'
    SAVE_PATH = f'/home/a/fuzz/DPfuzz/script/py/prediction/prediction_result/randomforest_fuzz'
    CSV_PATH = f'/home/a/fuzz/DPfuzz/script/py/prediction/PUT_features/{PROJECT}.csv'

    sourceDS = pd.read_csv(DATA_PATH)
    targetDS = pd.read_csv(CSV_PATH)

    source_X = sourceDS.iloc[:,:-1]
    source_y = sourceDS.iloc[:,-1]

    target_X = targetDS.iloc[:, 1:]

    model = CORAL(RandomForestClassifier(n_estimators=25), Xt=target_X, random_state=0)
    model.fit(source_X, source_y)

    tmp = 0
    res = model.predict(target_X)
    res_list = []
    for i in res:
        if i[1] <= 0.0001:
            res_list.append(0)
        else:
            res_list.append(i[1])
        if i[1]>=0.5:
            tmp+=1
    print(PROJECT,tmp)
    title = ['PJ_FUNCTION','D']
    func_list = []

    with open(CSV_PATH, newline='') as csvfile:
        reader = csv.reader(csvfile)
        next(reader)
        func_list = [row[0] for row in reader]
    predata = list(zip(func_list,res_list))
    csv_file = open(SAVE_PATH+'/'+PROJECT+'.csv', 'w', newline='')
    writer = csv.writer(csv_file)
    writer.writerow(title)
    for i in predata:
        writer.writerow(i)
    csv_file.close()