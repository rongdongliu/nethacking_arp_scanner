package examples;

/**
 * Created by SV on 18.01.2016.
 */
public class PacketParser {
    private byte[] packet;
    PacketParser(byte[] bytes){
        packet = bytes;
    }

    public String getTargetMac(){
        byte[] mac = new byte[6];
        for (int i = 0; i < 6; i++){
            mac[i] = packet[i];
            //System.out.println((int)mac[i]);
        }
        return toHexadecimal(mac);
    }

    public String getSourceMac(){
        byte[] mac = new byte[6];
        int j = 0;
        for (int i = 6; i < 12; i++){
            mac[j] = packet[i];
            j++;
            //System.out.println((int)mac[i]);
        }

        return toHexadecimal(mac);
    }
    private static String toHexadecimal(byte[] digest){
        String hash = "";
        for(byte aux : digest) {
            int b = aux & 0xff;
            if (Integer.toHexString(b).length() == 1) hash += "0";
            hash += Integer.toHexString(b);
        }
        return hash;
    }

    public String getSourceMacVendorId(){
        byte[] mac = new byte[3];
        int j = 0;
        for (int i = 6; i < 9; i++){
            mac[j] = packet[i];
            j++;
            //System.out.println((int)mac[i]);
        }

        return toHexadecimal(mac);
    }

    public  boolean isArp(){
        return packet[12] == 8 && packet[13] == 6;
    }
    public  boolean isArpAnswer(){
        return packet[20] == 0 && packet[21] == 2;
    }

    public String getSourceIP(){
        String ip = "";
        for (int i = 28; i < 32; i++){
            ip += Byte.toUnsignedInt(packet[i]);
            if (i < 31){
                ip += ".";
            }
        }
        return ip;
    }
}
