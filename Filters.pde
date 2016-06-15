

/**
 *
 * @author Greddy
 */
public class Filters extends javax.swing.JFrame {

  /**
   * Creates new form Filtry
   */
  PacketCaptureClass f_packet;
  String[] fields = {"Source IP", "Source port", "Destination IP", "Destination port", "Source MAC", "Destination MAC", 
    "Length", "TTL", "Fragmentation Flags", "ICMP Type", "ICMP Code", "ARP Hardware type", "ARP Protocol type", "LLC DSAP address", "LLC SSAP address", 
    "HHTP Request URL", "HTTP Referer", "HTTP Request Method", "String"};
  //public PacketCapture f_packet;
  public Log f_log;
  int counter = 0;

  public Filters(PacketCaptureClass frame) {

    f_packet = frame;
    initComponents();
    Thread f_thread = new Thread();
    f_thread.start();
    table_model = (DefaultTableModel) jTable1.getModel();
    for (int i = 0; i < fields.length; i++) {
      jComboBox1.addItem(fields[i]);
    }
  }

  public void addString(Log retezec) {

    Object[] row = {retezec.l_IDs, retezec.l_Time, retezec.l_typ_header, retezec.l_IP_Source, retezec.l_Port_Source, retezec.l_IP_Destination, retezec.l_Port_Destination, retezec.l_other_content};
    table_model.insertRow(0, row);
  }

  public String[] getTimeFrom() {

    String timeStamp = jTextField1.getText();
    String[] time_fields = timeStamp.split(":");

    return time_fields;
  }

  public String[] getTimeTo() {

    String timeStamp = jTextField2.getText();
    String[] time_fields = timeStamp.split(":");

    return time_fields;
  }

  @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

    jScrollPane1 = new javax.swing.JScrollPane();
    jTable1 = new javax.swing.JTable();
    jButton1 = new javax.swing.JButton();
    jCheckBox1 = new javax.swing.JCheckBox();
    jCheckBox2 = new javax.swing.JCheckBox();
    jCheckBox3 = new javax.swing.JCheckBox();
    jCheckBox4 = new javax.swing.JCheckBox();
    jCheckBox5 = new javax.swing.JCheckBox();
    jCheckBox6 = new javax.swing.JCheckBox();
    jLabel1 = new javax.swing.JLabel();
    jTextField1 = new javax.swing.JTextField();
    jLabel2 = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();
    jTextField2 = new javax.swing.JTextField();
    jSeparator1 = new javax.swing.JSeparator();
    jScrollPane2 = new javax.swing.JScrollPane();
    jList1 = new javax.swing.JList();
    jLabel4 = new javax.swing.JLabel();
    jLabel5 = new javax.swing.JLabel();
    jButton3 = new javax.swing.JButton();
    jComboBox1 = new javax.swing.JComboBox();
    jLabel6 = new javax.swing.JLabel();
    jButton4 = new javax.swing.JButton();
    jTextField3 = new javax.swing.JTextField();
    jButton5 = new javax.swing.JButton();
    jLabel7 = new javax.swing.JLabel();
    jCheckBox7 = new javax.swing.JCheckBox();

    setDefaultCloseOperation(javax.swing.WindowConstants.DISPOSE_ON_CLOSE);

    jTable1.setModel(new javax.swing.table.DefaultTableModel(
      new Object [][] {

      }, 
      new String [] {
        "ID", "Čas", "Header", "Source IP", "Source port", "Destination IP", "Destination port"
      }
      ) {
        boolean[] canEdit = new boolean [] {
          false, false, false, false, false, false, true
    };

    public boolean isCellEditable(int rowIndex, int columnIndex) {
      return canEdit [columnIndex];
    }
  }
  );
  jTable1.setColumnSelectionAllowed(true);
  jScrollPane1.setViewportView(jTable1);
  jTable1.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);

  jButton1.setText("Start");
  jButton1.addActionListener(new java.awt.event.ActionListener() {
    public void actionPerformed(java.awt.event.ActionEvent evt) {
      jButton1ActionPerformed(evt);
    }
  }
  );

  jCheckBox1.setText("HTTP");

  jCheckBox2.setText("ARP");

  jCheckBox3.setText("ICMP");

  jCheckBox4.setText("TCP");

  jCheckBox5.setText("UDP");

  jCheckBox6.setText("Payload");

  jLabel1.setText("Time interval");

  jTextField1.setText("14:00:00");

  jLabel2.setText("From:");

  jLabel3.setText("To:");

  jTextField2.setText("18:00:00");

  jList1.setModel(listModel);
  jList1.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
  jList1.setToolTipText("");
  jScrollPane2.setViewportView(jList1);

  jLabel4.setText("Active filters:");

  jLabel5.setText("Filtering");

  jButton3.setText("Remove");
  jButton3.addActionListener(new java.awt.event.ActionListener() {
    public void actionPerformed(java.awt.event.ActionEvent evt) {
      jButton3ActionPerformed(evt);
    }
  }
  );

  jLabel6.setText("Add field from packet to filter:");

  jButton4.setText("Add");
  jButton4.addActionListener(new java.awt.event.ActionListener() {
    public void actionPerformed(java.awt.event.ActionEvent evt) {
      jButton4ActionPerformed(evt);
    }
  }
  );

  jButton5.setText("Save");
  jButton5.addActionListener(new java.awt.event.ActionListener() {
    public void actionPerformed(java.awt.event.ActionEvent evt) {
      jButton5ActionPerformed(evt);
    }
  }
  );

  jLabel7.setText("Save session:");

  jCheckBox7.setText("IPv6");


  javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
  getContentPane().setLayout(layout);
  layout.setHorizontalGroup(
    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
    .addContainerGap()
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addComponent(jSeparator1)
    .addComponent(jScrollPane1, javax.swing.GroupLayout.Alignment.TRAILING, javax.swing.GroupLayout.DEFAULT_SIZE, 1483, Short.MAX_VALUE)
    .addGroup(layout.createSequentialGroup()
    .addComponent(jLabel1)
    .addGap(0, 0, Short.MAX_VALUE)))
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
    .addComponent(jButton3)
    .addGap(18, 18, 18))
    .addComponent(jButton1)
    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 401, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addComponent(jLabel4))
    .addContainerGap())
    .addGroup(layout.createSequentialGroup()
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
    .addComponent(jLabel2)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jLabel3)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, 120, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addGap(172, 172, 172)
    .addComponent(jLabel7)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
    .addComponent(jButton5))
    .addComponent(jLabel5)
    .addGroup(layout.createSequentialGroup()
    .addComponent(jCheckBox3)
    .addGap(11, 11, 11)
    .addComponent(jCheckBox6)
    .addGap(18, 18, 18)
    .addComponent(jCheckBox1)
    .addGap(18, 18, 18)
    .addComponent(jCheckBox2)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jCheckBox5)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jCheckBox4)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addComponent(jCheckBox7))
    .addGroup(layout.createSequentialGroup()
    .addComponent(jLabel6)
    .addGap(18, 18, 18)
    .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
    .addGroup(layout.createSequentialGroup()
    .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, 310, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addGap(18, 18, 18)
    .addComponent(jButton4)))
    .addGap(0, 0, Short.MAX_VALUE))))
    );
  layout.setVerticalGroup(
    layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(layout.createSequentialGroup()
    .addGap(20, 20, 20)
    .addComponent(jLabel5)
    .addGap(18, 18, 18)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
    .addGroup(layout.createSequentialGroup()
    .addComponent(jButton1)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
    .addComponent(jLabel4)
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
    .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 383, javax.swing.GroupLayout.PREFERRED_SIZE))
    .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 522, javax.swing.GroupLayout.PREFERRED_SIZE))
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.UNRELATED)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
    .addComponent(jLabel1)
    .addComponent(jButton3))
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
    .addComponent(jSeparator1, javax.swing.GroupLayout.PREFERRED_SIZE, 10, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addGap(1, 1, 1)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
    .addComponent(jTextField1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addComponent(jLabel2)
    .addComponent(jLabel3)
    .addComponent(jTextField2, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addComponent(jButton5)
    .addComponent(jLabel7))
    .addGap(18, 18, 18)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
    .addComponent(jCheckBox6)
    .addComponent(jCheckBox1)
    .addComponent(jCheckBox2)
    .addComponent(jCheckBox5)
    .addComponent(jCheckBox4)
    .addComponent(jCheckBox7))
    .addComponent(jCheckBox3))
    .addGap(11, 11, 11)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
    .addComponent(jLabel6)
    .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE))
    .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
    .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
    .addComponent(jTextField3, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
    .addComponent(jButton4))
    .addContainerGap(84, Short.MAX_VALUE))
    );

  pack();
}// </editor-fold>                        

private void jButton1ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:
  table_model.setRowCount(0);
  run();
}                                        

private void jButton4ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:
  String comboBox_tmp = jComboBox1.getSelectedItem().toString();
  String text_tmp = jTextField3.getText();
  listModel.addElement(comboBox_tmp + " - " + text_tmp);
  jTextField3.setText("");
}                                        

private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:
  listModel.removeElementAt(jList1.getSelectedIndex());
}                                        

private void jButton5ActionPerformed(java.awt.event.ActionEvent evt) {                                         

  for (int i = 0; i < jTable1.getRowCount(); i++) {

    String t_tmp_ID = jTable1.getModel().getValueAt(i, 0).toString();
    String fname = "pcaps\\" + t_tmp_ID + ".cap";
    String destfname = "filter\\" + t_tmp_ID + ".cap";
    StringBuilder errbuff = new StringBuilder();
    Pcap pcap = Pcap.openOffline(fname, errbuff);
    final PcapDumper dumper = pcap.dumpOpen(destfname);

    PcapPacketHandler<String> jpacketHandler;
    jpacketHandler = new PcapPacketHandler<String>() {
      public void nextPacket(PcapPacket packet, String user) {

        dumper.dump(packet);
      }
    };

    pcap.loop(1, jpacketHandler, "");
    pcap.close();
    dumper.close();
  }
}                                        

public void run() {

  for (int i = 0; i < f_packet.jTable1.getRowCount(); i++) {

    String f_date = f_packet.jTable1.getModel().getValueAt(i, 1).toString();
    String f_protocol = f_packet.jTable1.getModel().getValueAt(i, 2).toString();
    String[] f_tmpdate = f_date.split(" ");
    String[] time_fields = f_tmpdate[3].split(":");

    int TimeFrom = Integer.parseInt(getTimeFrom()[0]) * 3600 + Integer.parseInt(getTimeFrom()[1]) * 60 + Integer.parseInt(getTimeFrom()[2]);
    int TimeFromPacket = Integer.parseInt(time_fields[0]) * 3600 + Integer.parseInt(time_fields[1]) * 60 + Integer.parseInt(time_fields[2]);
    int TimeTo = Integer.parseInt(getTimeTo()[0]) * 3600 + Integer.parseInt(getTimeTo()[1]) * 60 + Integer.parseInt(getTimeTo()[2]);

    if (TimeFrom <= TimeFromPacket && TimeFromPacket <= TimeTo) {

      int f_IDs = Integer.parseInt(f_packet.jTable1.getModel().getValueAt(i, 0).toString());
      String f_src_IP = f_packet.jTable1.getModel().getValueAt(i, 3).toString();
      int f_src_port = Integer.parseInt(f_packet.jTable1.getModel().getValueAt(i, 4).toString());
      String f_dst_IP = f_packet.jTable1.getModel().getValueAt(i, 5).toString();
      int f_dst_port = Integer.parseInt(f_packet.jTable1.getModel().getValueAt(i, 6).toString());

      if (jCheckBox4.isSelected() && f_protocol.equals("TCP")) {
        f_log = new Log(f_IDs, "TCP", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
      if (jCheckBox5.isSelected() && f_protocol.equals("UDP")) {
        f_log = new Log(f_IDs, "UDP", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
      if (jCheckBox1.isSelected() && f_protocol.equals("HTTP")) {
        f_log = new Log(f_IDs, "HTTP", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
      if (jCheckBox3.isSelected() && f_protocol.equals("ICMP")) {
        f_log = new Log(f_IDs, "HTTP", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
      if (jCheckBox2.isSelected() && f_protocol.equals("ARP")) {
        f_log = new Log(f_IDs, "ARP", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
      if (jCheckBox7.isSelected() && f_protocol.equals("IPV6")) {
        f_log = new Log(f_IDs, "IPV6", f_date, f_src_IP, f_src_port, f_dst_IP, f_dst_port, "");
        addString(f_log);
      }
    }
  }
}

DefaultListModel listModel = new DefaultListModel();
public DefaultTableModel table_model;
public boolean start_stop = false;
// Variables declaration - do not modify                     
private javax.swing.JButton jButton1;
private javax.swing.JButton jButton3;
private javax.swing.JButton jButton4;
private javax.swing.JButton jButton5;
public javax.swing.JCheckBox jCheckBox1;
private javax.swing.JCheckBox jCheckBox2;
private javax.swing.JCheckBox jCheckBox3;
public javax.swing.JCheckBox jCheckBox4;
public javax.swing.JCheckBox jCheckBox5;
public javax.swing.JCheckBox jCheckBox6;
private javax.swing.JCheckBox jCheckBox7;
private javax.swing.JComboBox<String> jComboBox1;
private javax.swing.JLabel jLabel1;
private javax.swing.JLabel jLabel2;
private javax.swing.JLabel jLabel3;
private javax.swing.JLabel jLabel4;
private javax.swing.JLabel jLabel5;
private javax.swing.JLabel jLabel6;
private javax.swing.JLabel jLabel7;
public javax.swing.JList<String> jList1;
private javax.swing.JScrollPane jScrollPane1;
private javax.swing.JScrollPane jScrollPane2;
private javax.swing.JSeparator jSeparator1;
private javax.swing.JTable jTable1;
private javax.swing.JTextField jTextField1;
private javax.swing.JTextField jTextField2;
private javax.swing.JTextField jTextField3;
// End of variables declaration                   
}