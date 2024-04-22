mkdir attack_generator/cia
mkdir attack_generator/qoa
:'
echo "Generating attack flows for MalFlow Percent:0.03"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.03 --output_file cia_0_03.pcap
echo "Generating attack flows for MalFlow Percent:0.05"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.05 --output_file cia_0_05.pcap
echo "Generating attack flows for MalFlow Percent:0.1"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.1 --output_file cia_0_1.pcap
echo "Generating attack flows for MalFlow Percent:0.3"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.3 --output_file cia_0_3.pcap
echo "Generating attack flows for MalFlow Percent:0.5"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.5 --output_file cia_0_5.pcap
echo "Generating attack flows for MalFlow Percent:1"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 1 --output_file cia_1.pcap
echo "Generating attack flows for MalFlow Percent:3"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 3 --output_file cia_3.pcap
echo "Generating attack flows for MalFlow Percent:5"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 5 --output_file cia_5.pcap
echo "Generating attack flows for MalFlow Percent:10"
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 10 --output_file cia_10.pcap
'
echo "Generating attack flows for MalFlow Percent:0.03"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.03 --output_file qoa_0_03.pcap
echo "Generating attack flows for MalFlow Percent:0.05"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.05 --output_file qoa_0_05.pcap
echo "Generating attack flows for MalFlow Percent:0.1"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.1 --output_file qoa_0_1.pcap
echo "Generating attack flows for MalFlow Percent:0.3"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.3 --output_file qoa_0_3.pcap
echo "Generating attack flows for MalFlow Percent:0.5"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.5 --output_file qoa_0_5.pcap
echo "Generating attack flows for MalFlow Percent:1"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 1 --output_file qoa_1.pcap
echo "Generating attack flows for MalFlow Percent:3"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 3 --output_file qoa_3.pcap
echo "Generating attack flows for MalFlow Percent:5"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 5 --output_file qoa_5.pcap
echo "Generating attack flows for MalFlow Percent:10"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 10 --output_file qoa_10.pcap

echo "Generating attack flows for MalFlow Percent:10"
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0 --output_file g_truth.pcap
