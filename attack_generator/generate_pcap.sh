mkdir attack_generator/cia
mkdir attack_generator/qoa
mkdir attack_generator/random

python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.03 --output_file cia_0_03.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.05 --output_file cia_0_05.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.1 --output_file cia_0_1.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.3 --output_file cia_0_3.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.5 --output_file cia_0_5.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 1 --output_file cia_1.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 3 --output_file cia_3.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 5 --output_file cia_5.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 7 --output_file cia_7.pcap && \
python3 attack_generator/cia.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 10 --output_file cia_10.pcap && \

python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.03 --output_file qoa_0_03.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.05 --output_file qoa_0_05.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.1 --output_file qoa_0_1.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.3 --output_file qoa_0_3.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.5 --output_file qoa_0_5.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 1 --output_file qoa_1.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 3 --output_file qoa_3.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 5 --output_file qoa_5.pcap && \
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 7 --output_file qoa_7.pcap &&
python3 attack_generator/qoa.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 10 --output_file qoa_10.pcap && \

python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.03 --output_file random_0_03.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.05 --output_file random_0_05.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.1 --output_file random_0_1.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.3 --output_file random_0_3.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 0.5 --output_file random_0_5.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 1 --output_file random_1.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 3 --output_file random_3.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 5 --output_file random_5.pcap && \
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 7 --output_file random_7.pcap
python3 attack_generator/randomflow.py --pcap caida_trace/110k_24k_caida.pcap --percent_malflows 10 --output_file random_10.pcap