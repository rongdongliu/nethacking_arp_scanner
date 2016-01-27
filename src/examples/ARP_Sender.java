package examples;

import pcap.Convert;
import pcap.Pcap;

/**
 * Created by SV on 18.01.2016.
 */
public class ARP_Sender implements Runnable {
    private int id;
    ARP_Sender(int ifaceId){
        id = ifaceId;
    }
    public void  run(){
        NET_Interface firstIface = new NET_Interface(id);

        String iface = firstIface.getName();
        String sourceIp = Convert.dec2hex(firstIface.getIp());
        String ipPrefix = firstIface.getIpPrefix();
        String sourceMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress());
        String targetMac = "ff:ff:ff ff:ff:ff";
        while (true) {
            for (int i = 0; i < 255; i++) {
                String targetIp = Convert.dec2hex(ipPrefix + Integer.toString(i));
                byte[] packet = Convert.hex2bytes( // ----- Ethernet
                        targetMac,                 // Destination: ff:ff:ff:ff:ff:ff
                        sourceMac,                 // Source: __:__:__:__:__:__
                        "08 06",                   // Type: ARP (0x0806)
                        // ----- ARP
                        "00 01",                   // Hardware type: Ethernet (1)
                        "08 00",                   // Protocol type: IPv4 (0x0800)
                        "06",                      // Hardware size: 6
                        "04",                      // Protocol size: 4
                        "00 01",                   // Opcode: request (1)
                        sourceMac,                 // Sender MAC address: 6 bytes
                        sourceIp,                  // Sender IP address:  4 bytes
                        targetMac,                 // Target MAC address: 6 bytes
                        targetIp                   // Target IP address:  4 bytes
                );

                Pcap.send(iface, packet);
            }
        }
    }

}
