# Packet Sniffer
**Disclaimer!** \
This packet sniffer program is shared for educational and research purposes only. The author Prodromos Nasis does not encourage or condone any unethical or illegal activities using this software. Any individual who chooses to use this program is solely responsible for their actions. The author shall not be held liable for any misuse of this software for unauthorized purposes, including but not limited to network intrusion, unauthorized access, or any other malicious activities.

By downloading, copying, or using this software, you agree that you will use it in compliance with all applicable laws, and you assume full responsibility for any consequences that may arise from its use.

This software is provided "as is," without any warranties or guarantees of any kind, either expressed or implied. The author makes no guarantees regarding the functionality, reliability, or suitability of this software for any purpose.

Users are advised to use this software in a lawful and ethical manner and to respect the privacy and rights of others.

**Please use this software responsibly and only in authorized and legal environments!**

## Description
A packet sniffer, also known as a network sniffer or protocol analyzer, is a software or hardware tool used to capture and analyze network traffic. It allows network administrators or security professionals to examine the contents of packets transmitted over a network.

Packet sniffers work by intercepting and capturing network packets as they pass through a computer network interface. They can be deployed on a specific network interface or on a computer connected to a network in order to monitor the traffic flowing through that network.

Once the packets are captured, a packet sniffer decodes and analyzes their contents, providing detailed information about the communication between network devices. This information can include source and destination IP addresses, protocols used (such as HTTP, FTP, TCP, or UDP), port numbers, packet size, and even the actual data being transmitted.

Packet sniffers are commonly used for network troubleshooting, performance monitoring, network security analysis, and protocol development. However, it's important to note that the use of packet sniffers raises ethical and legal considerations, as they can potentially intercept sensitive information. Therefore, their usage should be done in compliance with applicable laws and regulations and with proper authorization.

***This program can capture and analyze only IP, TCP, UDP, ICMP and ARP packets!***
## Installation

Use the package manager apt (if you are using a debian based distro) to install pcap libraries.

```bash
sudo apt-get install libpcap-dev

```

## Usage

```Bash
# To compile the program
gcc -Wall -o sniffer sniffer.c -lpcap

# To run the program
sudo ./sniffer <interface>
```

## Contributing

>Pull requests are welcome. **For major changes, please open an issue first
to discuss what you would like to change.**


## License

>This project is under [Apache 2.0](https://choosealicense.com/licenses/apache-2.0/) licence.
