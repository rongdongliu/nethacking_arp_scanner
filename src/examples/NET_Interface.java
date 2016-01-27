package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Pcap;

import java.util.List;

/**
 * Created by SV on 18.01.2016.
 */
public class NET_Interface {

    private int ifaceNumber;

    NET_Interface(int number){
        ifaceNumber = number;
    }

    NET_Interface(){
        ifaceNumber = 0;
    }

    public String getName() {
        List<PcapNetworkInterface> devices = Pcap.interfaces();
        return devices.get(ifaceNumber).getName();
    }

    public String getIp() {
        List<PcapNetworkInterface>devices = Pcap.interfaces();
        List<PcapAddress> adresses = devices.get(ifaceNumber).getAddresses();
        String ip = "";
        for (PcapAddress adr: adresses){
            if (adr.getNetmask() != null){
                ip = adr.getAddress().toString().substring(1);
                break;
            }
        }
        return ip;
    }

    public String getIpPrefix() {
        String ip = this.getIp();
        return ip.substring(0, ip.lastIndexOf('.') + 1);
    }
}
