package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.io.Closeable;
import java.io.IOException;
import java.util.List;

public class Scanner {

    public static void main(String[] args) throws IOException {
        Thread senderThread = sendARPtoAllNetwork();

        NET_Interface firstIface = new NET_Interface(0);
        String iface = firstIface.getName();
        String myMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress()).replaceAll(" ", "" );
        System.out.println("My MAC: " + myMac);
        Closeable c  = Pcap.listen(iface, new Pcap.Listener() {
            public void onPacket(byte[] bytes) {
                PacketParser packet = new PacketParser(bytes);
                //System.out.println(packet.getSourceMac());
                if (packet.getTargetMac().equals(myMac)){
                    if (packet.isArp() && packet.isArpAnswer()){
                        System.out.println("ARP answer from " + packet.getSourceMac());
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
