NetScope - Advanced Packet Analyzer

NetScope is a powerful and user-friendly network packet analyzer with a sleek GUI built using PyQt5 and Scapy. It captures live network traffic, decodes and displays detailed packet information in real-time, providing insights similar to popular tools like Wireshark — all in a lightweight Python application.

Features

Live Packet Capture: Select network interfaces available on your system (Windows/Linux) and start capturing packets instantly.
Detailed Packet View: View comprehensive details of captured packets across multiple protocols including IP, TCP, UDP, ICMP, ARP, DNS, and HTTP.
Protocol Decoding: Automatically detect and display protocol-specific information such as TCP flags, HTTP methods and URLs, DNS queries/responses, ICMP types, and ARP operations.
Packet Table: Organized view with timestamp, source/destination IPs, protocols, ports, length, HTTP request method, and URLs.
Hex & ASCII Dump: Examine raw packet data in both hex and ASCII formats for in-depth analysis.
User-Friendly Interface: Intuitive controls to start/stop capture and browse through packets efficiently.
Cross-Platform: Works on Windows and Linux platforms.

Installation

Make sure you have Python 3.6+ installed.

Install required dependencies:
pip install PyQt5 scapy psutil

Run the application:
python netscope.py

Usage

Select the network interface from the dropdown.
Click Start Capture to begin sniffing packets on the chosen interface.
Packets will appear in the table as they are captured.
Click on any packet row to view detailed decoded information and raw hex dump.
Click Stop Capture to end packet sniffing.

Ethical Notice

This tool is intended solely for educational and authorized network monitoring purposes. Unauthorized packet capturing on networks you do not own or have permission to monitor may be illegal and unethical.

License
This project is licensed under the MIT License. See the LICENSE file for details.
