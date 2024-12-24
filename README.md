# HTTP Sniffer GUI

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

