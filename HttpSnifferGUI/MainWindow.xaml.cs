using System;
using System.Text;
using System.Windows;
using SharpPcap;
using PacketDotNet;
using PacketDotNet.Ieee80211;

namespace HttpSnifferGUI
{
    public partial class MainWindow : Window
    {
        private ICaptureDevice? device;
        private CaptureDeviceList? devices;

        public MainWindow()
        {
            InitializeComponent();
            LoadNetworkInterfaces();
        }

        private void LoadNetworkInterfaces()
        {
            devices = CaptureDeviceList.Instance;
            if (devices.Count == 0)
            {
                MessageBox.Show("No network interfaces found!");
                return;
            }

            foreach (var dev in devices)
            {
                InterfaceList.Items.Add(dev.Description);
            }

            InterfaceList.SelectedIndex = 0;
        }

        private void StartCapture_Click(object sender, RoutedEventArgs e)
        {
            if (InterfaceList.SelectedIndex < 0)
            {
                MessageBox.Show("Please select a network interface.");
                return;
            }

            device = devices?[InterfaceList.SelectedIndex];
            if (device == null)
            {
                MessageBox.Show("Selected device is null.");
                return;
            }

            device.OnPacketArrival += new PacketArrivalEventHandler(Device_OnPacketArrival);
            device.Open(DeviceModes.Promiscuous);
            device.Filter = "tcp port 80 or tcp port 443";
            device.StartCapture();
            CapturedData.AppendText("Capture started...\n");
        }

        private void StopCapture_Click(object sender, RoutedEventArgs e)
        {
            if (device != null)
            {
                device.StopCapture();
                device.Close();
                CapturedData.AppendText("Capture stopped.\n");
            }
        }

        private void Device_OnPacketArrival(object sender, PacketCapture e)
        {
            try
            {
                var rawPacket = e.GetPacket();
                if (rawPacket != null)
                {
                    var byteArraySegment = new PacketDotNet.Utils.ByteArraySegment(rawPacket.Data);
                    var ethernetPacket = new EthernetPacket(byteArraySegment);
                    if (ethernetPacket != null)
                    {
                        string ethInfo = $"Ethernet packet: Source: {ethernetPacket.SourceHardwareAddress}, Destination: {ethernetPacket.DestinationHardwareAddress}";
                        Dispatcher.Invoke(() =>
                        {
                            CapturedData.AppendText(ethInfo + "\n");
                        });

                        var ipPacket = ethernetPacket.PayloadPacket as IPPacket;
                        if (ipPacket != null)
                        {
                            string ipInfo = $"IP packet: Source IP: {ipPacket.SourceAddress}, Destination IP: {ipPacket.DestinationAddress}, Protocol: {ipPacket.Protocol}";
                            Dispatcher.Invoke(() =>
                            {
                                CapturedData.AppendText(ipInfo + "\n");
                            });

                            if (ipPacket.PayloadPacket is TcpPacket tcpPacket)
                            {
                                string tcpInfo = $"TCP packet: Source Port: {tcpPacket.SourcePort}, Destination Port: {tcpPacket.DestinationPort}, Flags: {tcpPacket.Flags}";
                                Dispatcher.Invoke(() =>
                                {
                                    CapturedData.AppendText(tcpInfo + "\n");
                                });

                                if (tcpPacket.DestinationPort == 80 || tcpPacket.DestinationPort == 443)
                                {
                                    var data = tcpPacket.PayloadData;
                                    string packetData;
                                    try
                                    {
                                        packetData = Encoding.ASCII.GetString(data);
                                        if (IsText(packetData))
                                        {
                                            Dispatcher.Invoke(() =>
                                            {
                                                CapturedData.AppendText($"Captured HTTP/HTTPS packet data:\n{packetData}\n");
                                            });
                                        }
                                        else
                                        {
                                            Dispatcher.Invoke(() =>
                                            {
                                                CapturedData.AppendText("Captured binary data (not readable as text).\n");
                                            });
                                        }
                                    }
                                    catch
                                    {
                                        Dispatcher.Invoke(() =>
                                        {
                                            CapturedData.AppendText("Captured data cannot be decoded as text.\n");
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Dispatcher.Invoke(() =>
                {
                    CapturedData.AppendText($"Error: {ex.Message}\n");
                });
            }
        }

        private bool IsText(string data)
        {
            return data.All(c => c >= 32 && c <= 126); // ASCII printable characters
        }

        private bool IsXSSVulnerable(string data)
        {
            return data.Contains("document.cookie") || data.Contains("alert(document.cookie)") ||
                   data.Contains("<script>") || data.Contains("<a href") || data.Contains("<input");
        }
    }
}
