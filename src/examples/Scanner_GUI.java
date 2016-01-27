package examples;

import org.pcap4j.core.PcapAddress;
import org.pcap4j.core.PcapNetworkInterface;
import pcap.Convert;
import pcap.Pcap;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.Closeable;
import java.io.IOException;
import java.util.*;

import javax.swing.*;


public class Scanner_GUI extends JFrame {

    private static JTextArea console;
    private static JComboBox ifaceBox;
    private static Thread senderThread;
    private static boolean scanStarted = false;
    private Closeable c;

    public Scanner_GUI() {
        super("ARP Scanner");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);

        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new BorderLayout(5, 5));
        mainPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));


        console = new JTextArea(20, 60);
        console.setFont(new Font("Arial", Font.PLAIN, 14));
        console.setEditable(false);
        mainPanel.add(new JScrollPane(console), BorderLayout.CENTER);

        JPanel buttonsPanel = new JPanel();
        buttonsPanel.setLayout(new BoxLayout(buttonsPanel, BoxLayout.LINE_AXIS));
        mainPanel.add(buttonsPanel, BorderLayout.NORTH);

        ifaceBox = new JComboBox();
        fillIfaceBox();
        buttonsPanel.add(ifaceBox);

        JButton scanButton = new JButton("Scan");
        scanButton.setFocusable(false);

        scanButton.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {

                if (!scanStarted) {
                    console.setText("");
                    scanStarted = true;
                    ifaceBox.setEnabled(false);
                    try {
                        scan(ifaceBox.getSelectedIndex());
                    } catch (Exception e1) {
                        e1.printStackTrace();
                    }
                    scanButton.setText("Stop");
                } else {
                    try {
                        c.close();
                    } catch (IOException e1) {
                        e1.printStackTrace();
                    }
                    ifaceBox.setEnabled(true);
                    scanStarted = false;
                    senderThread.stop();
                    scanButton.setText("Scan");

                }

            }
        });
        buttonsPanel.add(scanButton);

        getContentPane().add(mainPanel);

        pack();
        setLocationRelativeTo(null);
        setVisible(true);
    }

    private void fillIfaceBox() {
        for (PcapNetworkInterface dev : Pcap.interfaces()) {
            String ip = "";
            java.util.List<PcapAddress> adresses = dev.getAddresses();
            for (PcapAddress adr : adresses) {

                if (adr.getNetmask() != null) {
                    ip = adr.getAddress().toString().substring(1);
                    break;
                }
            }
            ifaceBox.addItem(dev.getName() + "  " + ip);
        }
    }

    public static void main(String[] args) {
        javax.swing.SwingUtilities.invokeLater(new Runnable() {
            public void run() {
                new Scanner_GUI();
            }
        });
    }

    private void scan(int ifaceId) throws IOException {
        senderThread = sendARPtoAllNetwork(ifaceId);
        Vendor_Base vendors = new Vendor_Base();
        NET_Interface firstIface = new NET_Interface(ifaceId);
        Set<String> inNetWork = new HashSet<String>();
        String iface = firstIface.getName();
        String myMac = Convert.bytes2hex(Pcap.get(iface).getLinkLayerAddresses().get(0).getAddress()).replaceAll(" ", "");
        c = Pcap.listen(iface, new Pcap.Listener() {
            public void onPacket(byte[] bytes) {
                PacketParser packet = new PacketParser(bytes);
                if (scanStarted) {
                    if (packet.getTargetMac().equals(myMac) && packet.isArp() && packet.isArpAnswer()) {
                        String sourceMac = packet.getSourceMac();
                        if (!inNetWork.contains(sourceMac)) {
                            String currentLanClient = ("MAC: " +
                                    sourceMac +
                                    " IP: " +
                                    packet.getSourceIP() +
                                    " Vendor: " +
                                    vendors.getVendorName(packet.getSourceMacVendorId().toUpperCase()));
                            console.setText(console.getText() + currentLanClient + "\n");
                            inNetWork.add(sourceMac);
                        }
                    }
                }
            }
        });

    }

    private static Thread sendARPtoAllNetwork(int ifaceId) {
        ARP_Sender sender = new ARP_Sender(ifaceId);
        Thread newThread = new Thread(sender);
        newThread.start();
        return newThread;
    }
}