import os 
import json
import pandas as pd

jsonMap = {}
fp = open("flowMap.json", 'w')
for root, _, files in os.walk('features'):
    for f in files:
        if f.endswith('.csv'):
            try:
                df = pd.read_csv(os.path.join(root, f))
                maxFlows = list(df['input_flows'])[-1] 
                filePath = os.path.join(root, f)
                key = '_'.join(filePath.split('_')[:-1]) + '.pcap'
                key = 'pcap_dataset/'+'/'.join(key.split('/')[1:])
                print(key)
                if key in jsonMap:
                    jsonMap[key] = max(jsonMap[key], maxFlows)
                else:
                    jsonMap[key] = maxFlows
            except pd.errors.EmptyDataError:
                print('CSV file is empty')
            except FileNotFoundError:
                print('CSV file not found')

json.dump(jsonMap,fp)