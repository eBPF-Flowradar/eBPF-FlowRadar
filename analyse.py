def dict_differences(dict1, dict2):
    # Keys in dict1 but not in dict2
    keys_only_in_dict1 = dict1.keys() - dict2.keys()

    # Keys in dict2 but not in dict1
    keys_only_in_dict2 = dict2.keys() - dict1.keys()

    # Keys in both with different values
    common_keys = dict1.keys() & dict2.keys()
    different_values = {key: (dict1[key], dict2[key]) for key in common_keys if dict1[key] != dict2[key]}

    # Summary of differences
    differences = {
        'Keys only in first dict (cd_flows)': keys_only_in_dict1,
        'Keys only in second dict (sniff_flows)': keys_only_in_dict2,
        'Different values': different_values
    }

    return differences




CD_FILE="cd_logs.csv"
SNIFF_FILE="sniff.csv"

cd_flows={}
sniff_flows={}

with open(CD_FILE) as file:
    for line in file:
        _,flow_id,pkt_count=line.strip().split(',')
        cd_flows[flow_id]=cd_flows.get(flow_id,0)+int(pkt_count)  

with open(SNIFF_FILE) as file:
    for line in file:
        _,flow_id=line.strip().split(',')
        sniff_flows[flow_id]=sniff_flows.get(flow_id,0)+1

#print(cd_flows)
#print(sniff_flows)

if cd_flows==sniff_flows:
    print("Equal")
else:
    print(dict_differences(cd_flows,sniff_flows))
