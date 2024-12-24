# HTTP Sniffer 

This is a simple HTTP/HTTPS packet sniffer built using C# and the `SharpPcap` and `PacketDotNet` libraries. It allows users to capture network traffic on selected network interfaces and inspect HTTP/HTTPS packet data.

## Features

- Capture network traffic on a selected network interface
- Display Ethernet, IP, and TCP packet information
- Decode and display HTTP/HTTPS packet data if available
- Basic support for detecting common XSS vulnerabilities in HTTP/HTTPS payloads

## Prerequisites

Before running the application, ensure that the following are installed on your machine:

- .NET Framework (preferably version 4.5 or higher)
- SharpPcap (for capturing packets)
- PacketDotNet (for parsing network packets)

You can install the required libraries via NuGet Package Manager or the following commands:



## Usage

1. **Start the Application**:
   Open the `HttpSnifferGUI` project in Visual Studio, and build the solution.

2. **Select a Network Interface**:
   When the application starts, it will display a list of available network interfaces. Select the network interface from which you want to capture packets.

3. **Start Capturing**:
   Click the "Start Capture" button to begin capturing network traffic. The sniffer will filter packets for HTTP (port 80) and HTTPS (port 443).

4. **Stop Capturing**:
   Click the "Stop Capture" button to stop capturing packets.

5. **View Captured Data**:
   The captured packet details (Ethernet, IP, TCP, and HTTP/HTTPS payloads) will be displayed in the "Captured Data" section. 

6. **Detect XSS Vulnerabilities**:
   The sniffer includes a basic XSS vulnerability detection mechanism. If a captured HTTP/HTTPS packet contains potential XSS patterns (e.g., `<script>`, `document.cookie`, etc.), it will be flagged.


## Troubleshooting

- **No Network Interfaces Found**: If no network interfaces are found, make sure your device has network adapters enabled and correctly configured.

- **Permission Issues**: On some systems, you may need administrative privileges to capture packets. Run the application as an administrator.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

