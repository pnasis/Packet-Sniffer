# Packet Sniffer

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

Please make sure to update tests as appropriate.

## License

>This project is under [Apache 2.0](https://choosealicense.com/licenses/apache-2.0/) licence.
