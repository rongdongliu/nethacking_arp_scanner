package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.Closeable;
import java.io.IOException;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class Scanner {

    public static void main(String[] args) throws Exception {
        Thread senderThread = sendARPtoAllNetwork();
        Vendor_Base vendors = new Vendor_Base();
        NET_Interface firstIface = new NET_Interface(0);
        Set<String> inNetWork = new HashSet<String>();
        String iface = firstIface.getName();
        //String iface = "\\Device\\NPF_{AD9CEB32-7E76-4201-9E6A-7E34081B9962}";
        String myMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress()).replaceAll(" ", "" );
        //System.out.println("My MAC: " + myMac);
        System.out.println("Now in the network: ");
        Closeable c  = Pcap.listen(iface, new Pcap.Listener() {
            public void onPacket(byte[] bytes) {
                PacketParser packet = new PacketParser(bytes);
                //System.out.println(packet.getSourceMac());
                if (packet.getTargetMac().equals(myMac)){
                    if (packet.isArp() && packet.isArpAnswer()){
                        //System.out.println(packet.getVendorId());
                        String sourceMac = packet.getSourceMac();

                        if(!inNetWork.contains(sourceMac))
                        System.out.println("MAC: " +
                                sourceMac +
                                " IP: " +
                                packet.getSourceIP() +
                                " Vendor: " +
                                vendors.getVendorName(packet.getSourceMacVendorId().toUpperCase()));
                        inNetWork.add(sourceMac);

                    }
                    //System.out.println("MY MAC");
                } else {
                    //System.out.println("---");
                }
            }
        });

//        System.err.println("Press Enter to close");
//        System.in.read(); // blocks here until user presses Enter
//
//        senderThread.stop();

    }

    private static Thread sendARPtoAllNetwork(){
        ARP_Sender sender = new ARP_Sender();
        Thread newThread = new Thread(sender);
        newThread.start();
        return newThread;
    }

}
