package examples;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by SV on 23.01.2016.
 */
public class Vendor_Base {
    Map<String, String> base = new HashMap<String, String>();

    Vendor_Base(){
        try (BufferedReader br = new BufferedReader(new FileReader("oui.txt"))) {
            //read line
            String line;
            while ((line = br.readLine()) != null) {
                if(line.indexOf("base 16") != -1){
                    String key = line.substring(0,6);
                    String nameCompany = line.substring(22);
                    base.put(key, nameCompany);
                }
            }
        } catch (IOException ex) {
            System.out.println(ex.getMessage());
        }

    }

    public String getVendorName(String vendorId){
        if (base.get(vendorId) == null){
            return  "Unknown vendor";
        }
        return base.get(vendorId);
    }
}
