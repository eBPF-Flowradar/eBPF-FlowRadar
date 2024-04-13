from ipaddress import ip_address
import struct



TCP="TCP"
UDP="UDP"
IPPROTO_TCP=6
IPPROTO_UDP=17

#format_string='<IIHHB'
format_string='<BHHII'
flow="11f6650462e793dad7f3be1cdd".rjust(26,"0")

flow_bytes=bytes.fromhex(flow)

protocol,dest_port,src_port,dest_ip,src_ip=struct.unpack(format_string,flow_bytes)

src_ip=str(ip_address(src_ip))
dest_ip=str(ip_address(dest_ip))

if protocol==IPPROTO_TCP:
    protocol=TCP
elif protocol==IPPROTO_UDP:
    protocol=UDP
else:
    protocol="unknown"

print(f"src_ip:{src_ip}\ndest_ip:{dest_ip}\nsrc_port:{src_port}\ndest_port:{dest_port}\nprotocol:{protocol}")

