# dns-spoofing
DNS spoofing

```
$ sudo apt update
$ sudo apt upgrade
$ sudo apt dist-upgrade

$ sudo apt install build-essential python-dev python3-dev libnetfilter-queue-dev
$ sudo apt install curl nmap tcpdump libpcap0.8

$ sudo apt install sudo apt install libnfnetlink-dev libnetfilter-conntrack-dev

$ sudo apt install python3-distutils python3-testresources
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
$ python3 get-pip.py --user
$ pip install -U pip

$ pip install matplotlib --user
$ pip install --pre scapy[basic] --user
#$ pip install --pre scapy[complete] --user

$ pip install netfilter --user
$ pip install netfilterqueue --user

$ sudo iptables -A OUTPUT -p udp --dport 53 -j NFQUEUE --queue-num 1
$ sudo iptables -L -nv

```
