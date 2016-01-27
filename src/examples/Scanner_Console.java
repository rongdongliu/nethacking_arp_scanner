package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.Closeable;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.List;
import java.util.Scanner;
import java.util.Set;

public class Scanner_Console {



    public static void main(String[] args) throws IOException {
        int ifaceId = getIfaceId();


        Thread senderThread = sendARPtoAllNetwork();
        Vendor_Base vendors = new Vendor_Base();
        NET_Interface firstIface = new NET_Interface(ifaceId);
        Set<String> inNetWork = new HashSet<String>();
        String iface = firstIface.getName();
        String myMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress()).replaceAll(" ", "" );
        System.out.println("Now in the network: ");
        Closeable c  = Pcap.listen(iface, new Pcap.Listener() {
            public void onPacket(byte[] bytes) {
                PacketParser packet = new PacketParser(bytes);
                if (packet.getTargetMac().equals(myMac)){
                    if (packet.isArp() && packet.isArpAnswer()){
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
                }
            }
        });

        System.err.println("Press Enter to close");
        System.in.read(); // blocks here until user presses Enter

        senderThread.stop();
        c.close();

    }

    private static int getIfaceId() {
        System.out.println("Found " + Pcap.interfaces().size() + " interfaces");
        System.out.println();
        int i = 0;
        for (PcapNetworkInterface dev : Pcap.interfaces()) {
            System.out.println(
                    "Number: " + i++ + "\n" +
                    "Name: " + dev.getName() + "\n" +
                    "IPs:  " + dev.getAddresses() + "\n" +
                    "MACs: " + dev.getLinkLayerAddresses() + "\n");
        }
        int id = -1;
        while (id < 0 || id > Pcap.interfaces().size() - 1) {
            System.out.print("Please enter interface number: ");
            Scanner sc = new Scanner(System.in);
            id = sc.nextInt();
        }
        return id;
    }

    private static Thread sendARPtoAllNetwork(){
        ARP_Sender sender = new ARP_Sender(0);
        Thread newThread = new Thread(sender);
        newThread.start();
        return newThread;
    }


}
