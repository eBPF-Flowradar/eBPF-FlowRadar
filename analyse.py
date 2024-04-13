
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

print(cd_flows)
print(sniff_flows)

if cd_flows==sniff_flows:
    print("Equal")
else:
    print("Not equal")
