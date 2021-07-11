# three-way-handshake
use raw socket to complete TCP three-way handshake

compile
```
make
```

kernel would send RST to server so use iptable to drop RST packet
```
sudo iptables -A OUTPUT -p tcp --tcp-flags RST RST -j DROP
```

usage
```
sudo ./three-way_handshake -s server_ip -p server_port -i host_ip
```
