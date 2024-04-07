'''
Combine instrumentation and defect prediction to ensure data consistency
'''
import csv
import sys
import tqdm
argv = sys.argv
if len(argv) > 1:
    PROJECT = argv[1]
else:
    exit()
func = 'randomforest_fuzz'
print(f'defect prediction ... witch {func}')
DPFuzzTMP_PATH = argv[2]
CSV_PATH = argv[3]
insFile = open(DPFuzzTMP_PATH+r'/instrumentation.txt', 'r')
insFileLines = insFile.readlines()
dataSet = {}
for l in tqdm.tqdm(insFileLines):
    if l:
        func = l.split(':')[0].split('/')[-1]+'@'+l.split(':')[1]
        if func not in dataSet.keys():
            dataSet[func] = {
                'BB': l.replace('\n', ''),
                'P': 0,
            }
with open(CSV_PATH, newline='') as csvfile:
    reader = csv.reader(csvfile)
    next(reader)
    for row in reader:
        if row[0].split('/')[-1] in dataSet.keys():
            dataSet[row[0].split('/')[-1]]['P'] = row[1]

preFile = open(DPFuzzTMP_PATH+'/prediction.txt', 'w')
for k, v in dataSet.items():
    preFile.write(str(v['P'])+'\n')
