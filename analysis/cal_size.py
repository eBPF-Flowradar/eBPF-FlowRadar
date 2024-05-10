import math

expected_no_of_flows=int(input("\nEnter expected number of flows: "))
fpr=float(input("Enter false positive rate: "))
ct_hash_count=int(input("Enter counting table hash count: "))

ck={
    3:1.222,
	4:1.295,
	5:1.425,
	6:1.570,
	7:1.721}

ff_hash_count=int(math.ceil(math.log(1 /fpr, 2)))
ff_bps=int(math.ceil((expected_no_of_flows * abs(math.log(fpr))) /(ff_hash_count * (math.log(2) ** 2))))
ct_eps=int(math.floor((int(expected_no_of_flows * ck[ct_hash_count]) + 10) / ct_hash_count)) 

print(f"\nFLOW_FILTER_HASH_COUNT: {ff_hash_count}")
print(f"FLOW_FILTER_BITS_PER_SLICE: {ff_bps}")
print(f"COUNTING_TABLE_ENTRIES_PER_SLICE: {ct_eps}")

print(f"FLOW_FILTER_SIZE: {ff_hash_count*ff_bps}")
print(f"COUNTING_TABLE_SIZE: {ct_hash_count*ct_eps}")
