
import javax.swing.tree.DefaultMutableTreeNode;
import javax.swing.tree.DefaultTreeModel;


public class packet_info extends javax.swing.JFrame {

    /**
     * Creates new form packet_info
     */
    ArrayList<String> headerList = new ArrayList<String>();
    ArrayList<String[]> headerContent = new ArrayList<String[]>();
    ArrayList<String> headerRowContent = new ArrayList<String>();
    DefaultMutableTreeNode root = new DefaultMutableTreeNode("Packet");
    DefaultTreeModel treeModel = new DefaultTreeModel(root);
    int countOfHeaders = 0;

    public packet_info() {
        initComponents();

    }

    public void set(int ID) {
      println(ID);

        //System.out.println(packet.toString());
        StringBuilder errbuff = new StringBuilder();
        String fname = sketchPath() + "\\data\\data" + ID + ".cap";
        System.out.println(fname);
        Pcap pcap = Pcap.openOffline(fname, errbuff);

        if (pcap == null) {
            System.err.printf("Error while opening device for capture: "
                    + errbuff.toString() + "\n");
            return;
        }

        PcapPacketHandler<String> jpacketHandlerr = new PcapPacketHandler<String>() {

            Http http = new Http();
            Arp arp = new Arp();
            Icmp icmp = new Icmp();
            Ip4 ip = new Ip4();
            Ip6 ip6 = new Ip6();
            Tcp tcp = new Tcp();
            Udp udp = new Udp();
            L2TP l2tp = new L2TP();
            PPP ppp = new PPP();
            Html html = new Html();
            WebImage webimage = new WebImage();
            Rtp rtp = new Rtp();
            Sdp sdp = new Sdp();
            Sip sip = new Sip();
            Ethernet eth = new Ethernet();
            IEEE802dot1q ieee = new IEEE802dot1q();
            IEEE802dot2 ieee2 = new IEEE802dot2();
            IEEE802dot3 ieee3 = new IEEE802dot3();
            IEEESnap ieees = new IEEESnap();
            SLL sll = new SLL();
            Payload payload = new Payload();
            URL url;

            @Override
            public void nextPacket(PcapPacket packet, String user) {

                packet.toString();
                countOfHeaders = packet.getHeaderCount();
                jTextArea1.append(packet.toString());

                if (packet.hasHeader(eth)) {
                    headerList.add("Ethernet");
                    String[] tst = packet.getHeader(eth).toString().split("Eth:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(ip)) {
                    headerList.add("IPv4");
                    String[] tst = packet.getHeader(ip).toString().split("Ip:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(ip6)) {
                    headerList.add("IPv6");
                    String[] tst = packet.getHeader(ip6).toString().split("Ipv6:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(tcp)) {
                    headerList.add("TCP");
                    String[] tst = packet.getHeader(tcp).toString().split("Tcp:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(udp)) {
                    headerList.add("UDP");
                    String[] tst = packet.getHeader(udp).toString().split("Udp:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(http)) {
                    headerList.add("HTTP");
                    String[] tst = packet.getHeader(http).toString().split("Http:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(arp)) {
                    headerList.add("ARP");
                    String[] tst = packet.getHeader(arp).toString().split("Arp:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(sip)) {
                    headerList.add("SIP");
                    String[] tst = packet.getHeader(sip).toString().split("Sip:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(icmp)) {
                    headerList.add("ICMP");
                    String[] tst = packet.getHeader(icmp).toString().split("Icmp:");
                    headerContent.add(tst);
                }
                if (packet.hasHeader(payload)) {
                    headerList.add("Payload");
                    String[] tst = packet.getHeader(payload).toString().split("\n");
                    headerContent.add(tst);
                }

            }
        };

        pcap.loop(-1, jpacketHandlerr, "");

        pcap.close();

        //create the root node
        //create the child nodes
        for (int i = 0; i < countOfHeaders; i++) {
            DefaultMutableTreeNode vegetableNode = new DefaultMutableTreeNode(headerList.get(i));
            System.out.println(headerList.get(i));
            String[] tst = headerContent.get(i);
            for (int y = 0; y < headerContent.get(i).length; y++) {
                vegetableNode.add(new DefaultMutableTreeNode(tst[y]));
                root.add(vegetableNode);
            }

        }

    }

    @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

        jScrollPane1 = new javax.swing.JScrollPane();
        jTextArea1 = new javax.swing.JTextArea();
        jScrollPane2 = new javax.swing.JScrollPane();
        jTree1 = new javax.swing.JTree();
        jLabel1 = new javax.swing.JLabel();
        jLabel2 = new javax.swing.JLabel();

        setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);
        setResizable(false);

        jTextArea1.setEditable(false);
        jTextArea1.setColumns(20);
        jTextArea1.setRows(5);
        jScrollPane1.setViewportView(jTextArea1);

        jTree1.setModel(treeModel);
        jScrollPane2.setViewportView(jTree1);

        jLabel1.setFont(new java.awt.Font("Tahoma", 0, 36)); // NOI18N
        jLabel1.setText("Packet viewer:");

        jLabel2.setFont(new java.awt.Font("Tahoma", 0, 24)); // NOI18N
        jLabel2.setText("Packet splited to Headers:");

        javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
        getContentPane().setLayout(layout);
        layout.setHorizontalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(100, 100, 100)
                .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
                    .addComponent(jLabel2)
                    .addComponent(jLabel1)
                    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
                        .addComponent(jScrollPane1, javax.swing.GroupLayout.DEFAULT_SIZE, 714, Short.MAX_VALUE)
                        .addComponent(jScrollPane2)))
                .addContainerGap(104, Short.MAX_VALUE))
        );
        layout.setVerticalGroup(
            layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
            .addGroup(layout.createSequentialGroup()
                .addGap(60, 60, 60)
                .addComponent(jLabel1)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 344, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addGap(40, 40, 40)
                .addComponent(jLabel2)
                .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
                .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 364, javax.swing.GroupLayout.PREFERRED_SIZE)
                .addContainerGap(99, Short.MAX_VALUE))
        );

        pack();
    }// </editor-fold>                        

    // Variables declaration - do not modify                     
    private javax.swing.JLabel jLabel1;
    private javax.swing.JLabel jLabel2;
    private javax.swing.JScrollPane jScrollPane1;
    private javax.swing.JScrollPane jScrollPane2;
    private javax.swing.JTextArea jTextArea1;
    private javax.swing.JTree jTree1;
    // End of variables declaration                   
}