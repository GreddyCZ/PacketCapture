import controlP5.*; //<>// //<>// //<>//
import javax.swing.JFrame;
import javax.swing.*;
import javax.swing.table.*;
import javax.swing.text.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.util.logging.*;
import javax.swing.text.BadLocationException;
import org.jnetpcap.Pcap;
import org.jnetpcap.PcapIf;
import java.text.SimpleDateFormat;
import com.maxmind.geoip2.DatabaseReader;
import com.maxmind.geoip2.exception.GeoIp2Exception;
import com.maxmind.geoip2.model.CountryResponse;
import com.maxmind.geoip2.record.Country;

/*
Co je treba dodelat
 veskere protokoly
 ukladani statistik
 prechod pcap do noveho v novem dni
 dalsi popisky do konzole
 celkova korekce kody - naposled
 */

int total_bytes = 0;

//////////////////////////////////////////////// GLOBAL////////////////////////////////////////////////////


List<NetworkDevice> DeviceList = new ArrayList<NetworkDevice>();
List<String> IPList = new ArrayList<String>();

public PacketCaptureClass cap;
public CaptureThread CapThread;
public DefaultTableModel table_model;
public DefaultTableModel table_model_2;
public DefaultTableModel table_model_3;
public Pcap pcap;
public boolean p_activation;
public int FirstRow = 0;
public int moveRow = 0;
public StyledDocument doc;

public String Local_MAC = new String();
public String IP_adress = "";
int packetX;
int packetY;
int packetW;
float packetH;
color[] colors;
int tmp_counter_packets;
float speed = 1;
String hostname = "";

ControlP5 cp5;
NetworkDevice thisComputer;
Filters f_filter;
SecondApplet secApplet;
UrlList urllist;
packet_info c_packet_info;

///////////////////////////////////////////////////////////////////////////////////////////////////////////
public void setup() {

  size(100, 100);
  surface.setSize(displayWidth/2 + displayWidth/4, displayHeight - displayHeight/5);
  surface.setLocation(100, 100);
  String[] args = {"Network Traffic"};
  secApplet = new SecondApplet();
  PApplet.runSketch(args, secApplet);
  noStroke();
  cap = new PacketCaptureClass();
  cap.setup();
  urllist = new UrlList();
  init();
}
void init() {

  try {

    InetAddress address = InetAddress.getLocalHost();
    IP_adress = address.getHostAddress();
    hostname = address.getHostName();
    NetworkInterface ni = NetworkInterface.getByInetAddress(address);
    if (ni != null) {
      byte[] byte_mac = ni.getHardwareAddress();
      if (byte_mac != null) {

        for (int i = 0; i < byte_mac.length; i++) {
          Local_MAC += String.format("%02X%s", byte_mac[i], (i < byte_mac.length - 1) ? ":" : "");
        }
        cap.addIP(IP_adress, Local_MAC, hostname);
        moveRow++;
      } else {
        System.out.println("Address doesn't exist");
      }
    } else {
      System.out.println("Network Interface for this IP address is not found.");
    }
  } 
  catch (UnknownHostException ex) {
    Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
  } 
  catch (SocketException ex) {
    Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
  }
}
void draw() {

  frameRate(60);

  background(142, 210, 213);
  fill(0);
  textSize(width/80);
  text("Network map", width/30, height/30);
  fill(164, 197, 158);
  rect(width/40, height/20, width, height);

  for (int i = 0; i < DeviceList.size(); i++) {

    fill(100, 0, 200);
    NetworkDevice tmp_device = DeviceList.get(i); 
    fill(0);
    rect(tmp_device.n_xPosition, tmp_device.n_yPosition, 10, 10);
    if (tmp_device.IPtime < 100) fill(255, 0, 0);
    if (tmp_device.IPtime >= 100 && tmp_device.IPtime < 200) fill(200, 100, 200);
    if (tmp_device.IPtime >= 200 && tmp_device.IPtime < 300) fill(10, 200, 20);
    if (tmp_device.IPtime >= 300 && tmp_device.IPtime < 400) fill(150, 10, 200);
    if (tmp_device.IPtime >= 400 && tmp_device.IPtime < 500) fill(0, 0, 200);

    if (tmp_device.destiny_xPosition > 10 )
      tmp_device.drawline();

    if (tmp_device.fontSize >= width/140) 
      tmp_device.fontSize --;

    if (DeviceList.size() > 55) {
      tmp_device.IPtime += 25;
      speed = 2;
    } else tmp_device.IPtime += 5;

    if (tmp_device.IPtime >= 500 ) {
      DeviceList.remove(DeviceList.get(i));
    }
    fill(0);
    textSize(tmp_device.fontSize);
    text(tmp_device.n_IP_Address, tmp_device.n_xPosition, tmp_device.n_yPosition + 25);
  }
}
public class SecondApplet extends PApplet {

  packet_traffic[] traffic;
  boolean visibility = false;

  public void setup() {
    surface.setSize(displayWidth - displayWidth/4, 1*displayHeight/4);
    surface.setLocation(0, 0);
    colors = new color[7]; 
    traffic = new packet_traffic[255000];
    color_generate();
    surface.setVisible(visibility);

    init();
  }
  void init() {

    cp5 = new ControlP5(this);

    cp5.addSlider("Speed")
      .setPosition(width/20, 22*height/25)
      .setWidth(200)
      .setRange(0.2, 2) // values can range from big to small as well
      .setValue(1)
      .setNumberOfTickMarks(10)
      .setColorValue(color(0))
      .setColorActive(color(0, 120, 250))
      .setColorForeground(color(155))
      .setColorBackground(color(255, 0, 0))
      .setColorTickMark(color(0))
      .setId(1)
      ;

    packetX = width/20;
    packetY = 0;
    packetW = width/100;
    packetH = width/100;
    tmp_counter_packets = 0;
  }
  void setVisible() {

    if (visibility) {
      surface.setVisible(false);
      visibility = false;
    } else {
      surface.setVisible(true);
      visibility = true;
    }
  }

  void enviroment() {

    textSize(12);
    noStroke();
    fill(240, 235, 235);
    rect(0, packetY, width, height);

    fill(15, 105, 15);
    rect(0, packetY - 5, width, - height/20);
    fill(255);
    textSize(16);
    text("Packet Traffic", width/30, packetY - 20 );
    textSize(14);
    stroke(0);
    fill(0);
    text("TCP", width/80, packetY + height/15);
    text("UDP", width/80, packetY + height/15 + height/8);
    text("ICMP", width/80, packetY + height/15 + 2*height/8);
    text("ARP", width/80, packetY + height/15 + 3*height/8);
    text("IPv6", width/80, packetY + height/15 + 4*height/8);
    text("OTHER", width/80, packetY + height/15 + 5*height/8);

    for (int i=0; i<50; i++) {   

      if (i < 7) line(0, packetY + i*height/8, width, packetY + i*height/8);
      if (i < 6) {
        fill(colors[i]);
        rect(packetX, packetY + i*height/8, packetW, height/8);
      }
      line(packetX + packetW + i*300*speed, packetY, packetX + packetW + i*300*speed, packetY + 6*height/8);
      text(0.5*(i+1), packetX + packetW + (i+1)*300*speed, 20 + packetY + 6*height/8);
    }
  }
  public void draw() {

    background(255);
    rect(0, 0, 300, 300);
    enviroment();
    for (int i = 0; i<tmp_counter_packets; i++) {
      traffic[i].move();
    }
  }
  void color_generate() {

    colors[0] = color(0);
    colors[1] = color(50, 100, 255);
    colors[2] = color(255, 0, 0);
    colors[3] = color(0, 100, 0);
    colors[4] = color(150, 25, 220);
    colors[5] = color(255, 100, 0);
  }
  void controlEvent(ControlEvent theEvent) {

    switch(theEvent.getController().getId()) {
      case(1):
      speed = theEvent.getController().getValue();
      break;
    }
  }
}

class NetworkDevice {

  int n_xPosition;
  int n_yPosition;
  String n_IP_Address;
  String n_desIP_Address;
  float fontSize = width/100;
  int IPtime = 0;
  int destiny_xPosition = 10;
  int destiny_yPosition = 10;

  NetworkDevice(int x_coordinate, int y_coordinate, String IP_address, String desIP_address, int x_pos_des, int y_pos_des) {

    n_xPosition = x_coordinate;
    n_yPosition = y_coordinate;
    n_IP_Address = IP_address;
    n_desIP_Address = desIP_address;

    destiny_xPosition = x_pos_des;
    destiny_yPosition = y_pos_des;
  }
  public void drawline() {

    beginShape();
    vertex(n_xPosition+5, n_yPosition+5);
    vertex(destiny_xPosition+5, destiny_yPosition+5);
    vertex(n_xPosition+10, n_yPosition+10);
    endShape(CLOSE);
  }
}

public class packet_traffic {

  float p_X_position;
  int p_Y_position;
  int p_type;
  int p_offset;
  float p_Height;

  packet_traffic(int typeOfPacket, int sizeOfPacket) {

    p_X_position = packetX;
    p_Y_position = packetY;
    p_type = typeOfPacket;

    if (typeOfPacket == 0) p_offset = 0;
    if (typeOfPacket == 1) p_offset = secApplet.height/8;
    if (typeOfPacket == 2) p_offset = 2*secApplet.height/8;
    if (typeOfPacket == 3) p_offset = 3*secApplet.height/8;
    if (typeOfPacket == 4) p_offset = 4*secApplet.height/8; 
    if (typeOfPacket == 5) p_offset = 5*secApplet.height/8; 

    p_Height = map(sizeOfPacket, 0, 1600, 0, secApplet.height/8);
  }
  void move() {
    secApplet.noStroke();
    secApplet.fill(colors[p_type]);
    secApplet.rect(p_X_position, packetY + secApplet.height/8 + p_offset, packetW, -p_Height);
    p_X_position += speed*10;
  }
}

///////////////////////////////////////////////////////////////////////////////////////////////////////////
public class PacketCaptureClass extends javax.swing.JFrame {

  List<PcapIf> alldevs = new ArrayList<PcapIf>();   
  StringBuilder errbuf = new StringBuilder();
  DefaultComboBoxModel ComboModel;

  public PacketCaptureClass() {
    initComponents();

    ComboModel = (DefaultComboBoxModel) jComboBox1.getModel();
    table_model = (DefaultTableModel) jTable1.getModel();
    table_model_2 = (DefaultTableModel) jTable2.getModel();
    table_model_3 = (DefaultTableModel) jTable3.getModel();
    Object[] row = {443, 0};
    table_model_3.insertRow(0, row);
    try {
      doc.insertString(doc.getLength(), "Searching network Devices\n", doc.getStyle("regular"));
    } 
    catch (BadLocationException ex) {
      Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
    }

    searchDevice();
    try {
      doc.insertString(doc.getLength(), "Searching network Devices - Done!\n", doc.getStyle("regular"));
    } 
    catch (BadLocationException ex) {
      Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
    }

    jButton3.setEnabled(true);
  }
  public void setup() {

    cap.setVisible(true);
  }

  @SuppressWarnings("unchecked")
    // <editor-fold defaultstate="collapsed" desc="Generated Code">                          
    private void initComponents() {

    jScrollPane2 = new javax.swing.JScrollPane();
    jTextPane1 = createTextPane();
    jLabel2 = new javax.swing.JLabel();
    jLabel3 = new javax.swing.JLabel();
    jComboBox1 = new javax.swing.JComboBox();
    jScrollPane1 = new javax.swing.JScrollPane();
    jTable1 = new javax.swing.JTable();
    jButton3 = new javax.swing.JButton();
    jScrollPane3 = new javax.swing.JScrollPane();
    jTable2 = new javax.swing.JTable();
    jButton1 = new javax.swing.JButton();
    jButton4 = new javax.swing.JButton();
    jLabel4 = new javax.swing.JLabel();
    jButton6 = new javax.swing.JButton();
    jLabel5 = new javax.swing.JLabel();
    jButton7 = new javax.swing.JButton();
    jButton8 = new javax.swing.JButton();
    jButton9 = new javax.swing.JButton();
    jButton10 = new javax.swing.JButton();
    jLabel6 = new javax.swing.JLabel();
    jScrollPane4 = new javax.swing.JScrollPane();
    jTable3 = new javax.swing.JTable();
    jLabel7 = new javax.swing.JLabel();

    setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
    setCursor(new java.awt.Cursor(java.awt.Cursor.DEFAULT_CURSOR));
    setMinimumSize(new java.awt.Dimension(width, 3*height/4));
    setMaximumSize(new java.awt.Dimension(width, height));
    setPreferredSize(new java.awt.Dimension(width, height));
    setResizable(true);
    setSize(new java.awt.Dimension(width, height));


    jScrollPane2.setAutoscrolls(true);
    jScrollPane2.setViewportView(jTextPane1);

    jLabel2.setText("Console");

    jLabel3.setText("Logs");
    jLabel3.setToolTipText("");

    jTable1.setModel(new javax.swing.table.DefaultTableModel(
      new Object [][] {

      }, 
      new String [] {
        "ID", "Time", "Header", "Source IP", "Source port", "Destination IP", "Destination port", "More info"
      }
      ) {
        boolean[] canEdit = new boolean [] {
          false, false, false, false, false, false, false, false
    };

    public boolean isCellEditable(int rowIndex, int columnIndex) {
      return canEdit [columnIndex];
    }
  }
  );
  jTable1.getColumnModel().getColumn(0).setPreferredWidth(20);
  jTable1.getColumnModel().getColumn(2).setPreferredWidth(20);
  jTable1.getColumnModel().getColumn(4).setPreferredWidth(20);
  jTable1.getColumnModel().getColumn(6).setPreferredWidth(20);
  jTable1.getColumnModel().getColumn(7).setPreferredWidth(100);
  jTable1.setAutoscrolls(false);
  jTable1.setColumnSelectionAllowed(true);
  jTable1.setCellSelectionEnabled(false);
  jTable1.setMinimumSize(new java.awt.Dimension(0, 0));
  jTable1.setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
  jTable1.addMouseListener(new java.awt.event.MouseAdapter() {
    public void mouseClicked(java.awt.event.MouseEvent evt) {
      jTable1MouseClicked(evt);
    }
  }
  );
  jScrollPane1.setViewportView(jTable1);
  jTable1.getColumnModel().getSelectionModel().setSelectionMode(javax.swing.ListSelectionModel.SINGLE_SELECTION);
  jTable1.setRowSelectionAllowed(true);

  jButton3.setText("Start / Stop");
  jButton3.setToolTipText("");
  jButton3.setEnabled(true);
  jButton3.addActionListener(new java.awt.event.ActionListener() {
    public void actionPerformed(java.awt.event.ActionEvent evt) {
      jButton3ActionPerformed(evt);
    }
  }
  );

  jTable2.setModel(new javax.swing.table.DefaultTableModel(
    new Object [][] {

    }, 
    new String [] {
      "IP", "MAC", "Data (Down / Up)", "Device name", "Country"
    }
    ) {
      boolean[] canEdit = new boolean [] {
        false, false, false, true, false
  };

  public boolean isCellEditable(int rowIndex, int columnIndex) {
    return canEdit [columnIndex];
  }
}
);
jScrollPane3.setViewportView(jTable2);
if (jTable2.getColumnModel().getColumnCount() > 0) {
  jTable2.getColumnModel().getColumn(1).setResizable(true);
  jTable2.getColumnModel().getColumn(2).setResizable(true);
}

jButton1.setText("+");
jButton1.setToolTipText("Add row");
jButton1.addMouseListener(new java.awt.event.MouseAdapter() {
  public void mouseClicked(java.awt.event.MouseEvent evt) {
    jButton1MouseClicked(evt);
  }
}
);

jButton4.setText("Clear All");
jButton4.addMouseListener(new java.awt.event.MouseAdapter() {
  public void mouseClicked(java.awt.event.MouseEvent evt) {
    jButton4MouseClicked(evt);
  }
}
);

jLabel4.setText("View traffic:");

jButton6.setText("Show");
jButton6.addActionListener(new java.awt.event.ActionListener() {
  public void actionPerformed(java.awt.event.ActionEvent evt) {
    jButton6ActionPerformed(evt);
  }
}
);

jLabel5.setText("URL list:");

jButton7.setText("Show");
jButton7.addActionListener(new java.awt.event.ActionListener() {
  public void actionPerformed(java.awt.event.ActionEvent evt) {
    jButton7ActionPerformed(evt);
  }
}
);

jButton8.setText("Export to File");
jButton8.addActionListener(new java.awt.event.ActionListener() {
  public void actionPerformed(java.awt.event.ActionEvent evt) {
    jButton8ActionPerformed(evt);
  }
}
);

jButton9.setText("Activate");
jButton9.addActionListener(new java.awt.event.ActionListener() {
  public void actionPerformed(java.awt.event.ActionEvent evt) {
    jButton9ActionPerformed(evt);
  }
}
);

jButton10.setText("Show Window");
jButton10.addActionListener(new java.awt.event.ActionListener() {
  public void actionPerformed(java.awt.event.ActionEvent evt) {
    jButton10ActionPerformed(evt);
  }
}
);

jLabel6.setText("Filtering:");

jTable3.setModel(new javax.swing.table.DefaultTableModel(
  new Object [][] {

  }, 
  new String [] {
    "Port", "Count"
  }
  ) {
    boolean[] canEdit = new boolean [] {
      false, false
};

public boolean isCellEditable(int rowIndex, int columnIndex) {
  return canEdit [columnIndex];
}
});
jScrollPane4.setViewportView(jTable3);

jLabel7.setText("Statistic of used port");

javax.swing.GroupLayout layout = new javax.swing.GroupLayout(getContentPane());
getContentPane().setLayout(layout);
layout.setHorizontalGroup(
  layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addGroup(javax.swing.GroupLayout.Alignment.TRAILING, layout.createSequentialGroup()
  .addGap(42, 42, 42)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
  .addGroup(layout.createSequentialGroup()
  .addComponent(jScrollPane1, javax.swing.GroupLayout.PREFERRED_SIZE, 3*width/5, javax.swing.GroupLayout.PREFERRED_SIZE)
  .addGap(28, 28, 28)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
  .addComponent(jScrollPane4, javax.swing.GroupLayout.PREFERRED_SIZE, width/5, javax.swing.GroupLayout.PREFERRED_SIZE)
  .addGroup(layout.createSequentialGroup()
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
  .addGroup(layout.createSequentialGroup()
  .addComponent(jButton9)
  .addGap(4, 4, 4)
  .addComponent(jButton3))
  .addGroup(layout.createSequentialGroup()
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addComponent(jLabel4)
  .addComponent(jLabel6)
  .addComponent(jLabel5))
  .addGap(18, 18, 18)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addComponent(jButton6)
  .addComponent(jButton7)
  .addComponent(jButton10)))
  .addComponent(jLabel7))
  .addGap(0, 0, Short.MAX_VALUE))))
  .addGroup(layout.createSequentialGroup()
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addComponent(jLabel2, javax.swing.GroupLayout.PREFERRED_SIZE, 206, javax.swing.GroupLayout.PREFERRED_SIZE)
  .addComponent(jLabel3)
  .addComponent(jScrollPane2, javax.swing.GroupLayout.PREFERRED_SIZE, 4*width/10, javax.swing.GroupLayout.PREFERRED_SIZE))
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addGroup(layout.createSequentialGroup()
  .addGap(28, 28, 28)
  .addComponent(jButton4)
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addComponent(jButton1)
  .addGap(18, 18, 18)
  .addComponent(jButton8))
  .addGroup(layout.createSequentialGroup()
  .addGap(18, 18, 18)
  .addComponent(jScrollPane3, javax.swing.GroupLayout.PREFERRED_SIZE, 9*width/20, javax.swing.GroupLayout.PREFERRED_SIZE)))))
  .addContainerGap(javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
  );
layout.setVerticalGroup(
  layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addGroup(layout.createSequentialGroup()
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING)
  .addGroup(layout.createSequentialGroup()
  .addGap(42, 42, 42)
  .addComponent(jLabel3)
  .addGap(18, 18, 18)
  .addComponent(jScrollPane1))
  .addGroup(layout.createSequentialGroup()
  .addGap(79, 79, 79)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
  .addComponent(jButton3)
  .addComponent(jButton9))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addComponent(jComboBox1, javax.swing.GroupLayout.PREFERRED_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)
  .addGap(44, 44, 44)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
  .addComponent(jLabel4)
  .addComponent(jButton6))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
  .addComponent(jButton7)
  .addComponent(jLabel5))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
  .addComponent(jButton10)
  .addComponent(jLabel6))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED, javax.swing.GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
  .addComponent(jLabel7)
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addComponent(jScrollPane4, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.DEFAULT_SIZE, javax.swing.GroupLayout.PREFERRED_SIZE)))
  .addGap(18, 18, 18)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.BASELINE)
  .addComponent(jLabel2)
  .addComponent(jButton4)
  .addComponent(jButton1)
  .addComponent(jButton8))
  .addPreferredGap(javax.swing.LayoutStyle.ComponentPlacement.RELATED)
  .addGroup(layout.createParallelGroup(javax.swing.GroupLayout.Alignment.LEADING, false)
  .addComponent(jScrollPane3, javax.swing.GroupLayout.DEFAULT_SIZE, height/6, Short.MAX_VALUE)
  .addComponent(jScrollPane2))
  .addGap(45, 45, 45))
  );

pack();
}                        

private void jButton3ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:

  int response = JOptionPane.showConfirmDialog(null, "Do you want to continue?", "Confirm", 
    JOptionPane.YES_NO_OPTION, JOptionPane.QUESTION_MESSAGE);
  switch (response) {
  case JOptionPane.NO_OPTION:
    System.out.println("No button clicked");
    break;
  case JOptionPane.YES_OPTION:
    if (p_activation == true) {
      pcap.breakloop();
      p_activation = false;
      try {
        doc.insertString(doc.getLength(), "Attention!!! Capturing packets is stopped\n", doc.getStyle("regular"));
      } 
      catch (BadLocationException ex) {
        Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
      }
    } else {

      initDevice();
      p_activation = true;
      CapThread = new CaptureThread();
      //t.start();
      try {
        doc.insertString(doc.getLength(), new Date() + "  Capturing packets is active! \n", doc.getStyle("regular"));
      } 
      catch (BadLocationException ex) {
        Logger.getLogger(PacketCapture.class.getName()).log(Level.SEVERE, null, ex);
      }
    }
    break;
  case JOptionPane.CLOSED_OPTION:
    System.out.println("JOptionPane closed");
    break;
  default:
    break;
  }
}                                        

private void jTable1MouseClicked(java.awt.event.MouseEvent evt) {                                     
  // TODO add your handling code here:
  if (evt.getClickCount() == 2) {
    JTable target = (JTable) evt.getSource();
    int row = target.getSelectedRow();
    Object tmp_IDs = target.getModel().getValueAt(row, 0);
    c_packet_info = new packet_info();
    c_packet_info.setVisible(true);
    c_packet_info.set((Integer) tmp_IDs);
  }
}                                   

private void jButton1MouseClicked(java.awt.event.MouseEvent evt) {                                      
  // TODO add your handling code here:
  Object[] new_row = {"", "", 0, ""};
  table_model_2.insertRow(jTable2.getRowCount(), new_row);
}  
private void jButton4MouseClicked(java.awt.event.MouseEvent evt) {                                      
  // TODO add your handling code here:
  table_model_2.setNumRows(0);
  moveRow = 0;
  addIP(IP_adress, Local_MAC, hostname);
  moveRow++;
}   
private void jButton9ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:

  initDevice();
  jButton9.setEnabled(false);
  p_activation = false;
}                                                                         

private void jButton10ActionPerformed(java.awt.event.ActionEvent evt) {                                          
  // TODO add your handling code here:
  f_filter = new Filters(cap);
  f_filter.setVisible(true);
}                                         

private void jButton8ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:

  JFileChooser fileChooser = new JFileChooser();
  fileChooser.setDialogTitle("Specify a file to save");
  int userSelection = fileChooser.showSaveDialog(this);

  if (userSelection == JFileChooser.APPROVE_OPTION) {
    File fileToSave = fileChooser.getSelectedFile();
    writeToFile(fileToSave.getAbsolutePath());
    System.out.println("Save as file: " + fileToSave.getAbsolutePath());
  }
}                                        

private void jButton7ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:
  urllist.setVisible(true);
}                                        

private void jButton6ActionPerformed(java.awt.event.ActionEvent evt) {                                         
  // TODO add your handling code here:
  secApplet.setVisible();
} 
private JTextPane createTextPane() {

  JTextPane textPane = new JTextPane();
  doc = textPane.getStyledDocument();
  addStylesToDocument(doc);

  return textPane;
}
public void writeToFile(String path) {

  try {

    File statText = new File(path + ".txt");
    FileOutputStream FileStream = new FileOutputStream(statText);
    OutputStreamWriter OutputWriter = new OutputStreamWriter(FileStream);
    Writer W_writer = new BufferedWriter(OutputWriter);
    W_writer.write("File was generated: " + new Date() + "\n");
    for (int i = 0; i < jTable2.getRowCount(); i++) {
      W_writer.write("IP adress: " + table_model_2.getValueAt(i, 0) + " ; MAC address: "
        + table_model_2.getValueAt(i, 1) + " ; Transferred Data (Down / Up):  "
        + table_model_2.getValueAt(i, 2) + " Bytes" + " ; Device name: " + table_model_2.getValueAt(i, 3) + "\n");
    }
    W_writer.write("Created by Petr Hvižď, 2016");
    W_writer.close();
  } 
  catch (IOException e) {
    System.err.println("Problem writing to the file");
  }
}
public void addPort(int t_port) {

  boolean IsInTable = false;
  int tmp_position = 0;
  for (int i = 0; i < jTable3.getRowCount(); i++) {
    int t_tmp_port = Integer.parseInt(jTable3.getModel().getValueAt(i, 0).toString());
    if (t_tmp_port == t_port) {
      IsInTable = true;
      tmp_position = i;
      break;
    } else {
      IsInTable = false;
    }
  }

  if (IsInTable) {
    int t_tmp_count = Integer.parseInt(jTable3.getModel().getValueAt(tmp_position, 1).toString());
    t_tmp_count++;
    jTable3.getModel().setValueAt(t_tmp_count, tmp_position, 1);
  } else {
    Object[] row = {t_port, 0};
    table_model_3.insertRow(0, row);
  }
  bubbleSort();
}

public void bubbleSort() {

  for (int i = 0; i < jTable3.getRowCount(); i++) {

    for (int j = 0; j < jTable3.getRowCount() - i - 1; j++) {

      if (Integer.parseInt(jTable3.getModel().getValueAt(j, 0).toString()) > Integer.parseInt(jTable3.getModel().getValueAt(j+1, 0).toString())) {

        int tmp = Integer.parseInt(jTable3.getModel().getValueAt(j, 0).toString());
        int tmp_c = Integer.parseInt(jTable3.getModel().getValueAt(j, 1).toString());
        jTable3.getModel().setValueAt(Integer.parseInt(jTable3.getModel().getValueAt(j+1, 0).toString()), j, 0);
        jTable3.getModel().setValueAt(Integer.parseInt(jTable3.getModel().getValueAt(j+1, 1).toString()), j, 1);
        jTable3.getModel().setValueAt(tmp, j+1, 0);
        jTable3.getModel().setValueAt(tmp_c, j+1, 1);
      }
    }
  }
}
public void addIP(String IP, String MAC, String hostname) {

  File database = new File("C:\\Users\\Greddy\\Downloads\\GeoLite2-Country.mmdb\\GeoLite2-Country.mmdb");

  DatabaseReader reader = null;
  try {
    reader = new DatabaseReader.Builder(database).build();
  } 
  catch (IOException ex) {
    Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
  }

  InetAddress ipAddress = null;
  try {
    ipAddress = InetAddress.getByName(IP);
  } 
  catch (UnknownHostException ex) {
    Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
  }

  if (FirstRow == 0) {
    Object[] first_row = {IP, MAC, "0/0", hostname};
    table_model_2.insertRow(0, first_row);
    FirstRow++;
  } else {

    String[] tmp_IP = IP.split("\\.");

    if (IP.matches("(.*):(.*)") == true || tmp_IP[0].equals("192") || tmp_IP[0].equals("239") || tmp_IP[0].equals("0") || tmp_IP[0].equals("224") || tmp_IP[0].equals("234") || tmp_IP[0].equals("255") ) {
      Object[] row = {IP, MAC, "0/0", "", "Inside network"};
      table_model_2.insertRow(moveRow, row);
    } else {
      CountryResponse response = null;

      try {
        response = reader.country(ipAddress);
      } 
      catch (IOException ex) {
        Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
      } 
      catch (GeoIp2Exception ex) {
        Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
      }

      Country country = response.getCountry();
      Object[] row = {IP, MAC, "0/0", "", country.getName()};
      table_model_2.insertRow(moveRow, row);
    }
  }
}

public void addString(Log retezec) {

  Object[] row = {retezec.l_IDs, retezec.l_Time, retezec.l_typ_header, retezec.l_IP_Source, retezec.l_Port_Source, retezec.l_IP_Destination, retezec.l_Port_Destination, retezec.l_other_content};
  table_model.insertRow(0, row);
}

public void addStylesToDocument(StyledDocument document) {

  Style def = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);

  Style regular = doc.addStyle("regular", def);
  StyleConstants.setFontFamily(def, "SanSerif");
}

public void initDevice() {

  int r = Pcap.findAllDevs(alldevs, errbuf);
  if (r == Pcap.WARNING || alldevs.isEmpty()) {
    try {
      doc.insertString(doc.getLength(), "Can't read list of devices, error is %s" + errbuf.toString() + "\n", doc.getStyle("regular"));
    } 
    catch (BadLocationException ex) {
      Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
    }
    return;
  }

  PcapIf device = alldevs.get(jComboBox1.getSelectedIndex());

  try {
    doc.insertString(doc.getLength(), "Selected Device: " + device.getDescription() + "\n", doc.getStyle("regular"));
  } 
  catch (BadLocationException ex) {
    Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
  }

  int snaplen = 64 * 1024;           // Capture all packets, no trucation  
  int flags = Pcap.MODE_PROMISCUOUS; // capture all packets  
  int timeout = 10;           // 10 millis  
  pcap = Pcap.openLive(device.getName(), snaplen, flags, timeout, errbuf);

  if (pcap == null) {

    try {
      doc.insertString(doc.getLength(), "Error while opening device for capture: "
        + errbuf.toString() + "\n", doc.getStyle("regular"));
    } 
    catch (BadLocationException ex) {
      Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
    }
    return;
  }
}

public void searchDevice() {

  ComboModel.removeAllElements();
  Pcap.freeAllDevs(alldevs, errbuf);
  int statusCode = Pcap.findAllDevs(alldevs, errbuf);
  if (statusCode != Pcap.OK) {
    try {
      doc.insertString(doc.getLength(), "Error occured: " + errbuf.toString() + "\n", doc.getStyle("regular"));
    } 
    catch (BadLocationException ex) {
      Logger.getLogger(CaptureThread.class.getName()).log(Level.SEVERE, null, ex);
    }
    return;
  }

  int index_device = 0;
  for (PcapIf device : alldevs) {
    String description
      = (device.getDescription() != null) ? device.getDescription()
      : "No description available";
    ComboModel.addElement((index_device++) + ") " + description);
  }
}

// Variables declaration - do not modify                     
private javax.swing.JButton jButton1;
private javax.swing.JButton jButton10;
private javax.swing.JButton jButton3;
private javax.swing.JButton jButton4;
private javax.swing.JButton jButton6;
private javax.swing.JButton jButton7;
private javax.swing.JButton jButton8;
private javax.swing.JButton jButton9;
public javax.swing.JComboBox<String> jComboBox1;
private javax.swing.JLabel jLabel1;
private javax.swing.JLabel jLabel2;
private javax.swing.JLabel jLabel3;
private javax.swing.JLabel jLabel4;
private javax.swing.JLabel jLabel5;
private javax.swing.JLabel jLabel6;
private javax.swing.JLabel jLabel7;
private javax.swing.JScrollPane jScrollPane1;
private javax.swing.JScrollPane jScrollPane2;
private javax.swing.JScrollPane jScrollPane3;
private javax.swing.JScrollPane jScrollPane4;
public javax.swing.JTable jTable1;
public javax.swing.JTable jTable2;
private javax.swing.JTable jTable3;
private javax.swing.JTextPane jTextPane1;
// End of variables declaration                   
}


class CaptureThread extends Thread {

  public Thread thread;  
  public String ofile;
  public Log m_log;
  public int IDs;
  public InetAddress this_IP;

  public CaptureThread() {

    thread = new Thread(this);
    this.start();
    thisComputer = new NetworkDevice(width/2, height/2, IP_adress, "", 0, 0);
    DeviceList.add(thisComputer);
  }
  public void CheckDevice(String _IP, String _IP_) {

    float temp_width = random(width/40, width - width/10);
    float temp_height = random(height/20, height-height/10);
    int x_pos = 0;
    int y_pos = 0;
    for (int i = 0; i < DeviceList.size(); i++) {
      NetworkDevice tmp_device = DeviceList.get(i);

      if (tmp_device.n_xPosition - 70 < temp_width && tmp_device.n_xPosition + 70 > temp_width  
        && tmp_device.n_yPosition - 50 < temp_height && tmp_device.n_yPosition + 50 > temp_height ) {
        temp_width = random(width/40, width - width/10);
        temp_height = random(height/20, height-height/10);
        i = 0;
      }
    }
    NetworkDevice new_Computer = new NetworkDevice((int)temp_width, (int)temp_height, _IP, _IP_, x_pos, y_pos);
    DeviceList.add(new_Computer);
  }

  void CheckIP(String Source_IP, String Destination_IP, String Source_MAC, String Destination_MAC, boolean isHeaderIPv4, double sizeofPacket) {

    boolean destinyIs = true;
    boolean sourceIs = true;
    String[] IP_tmp;
    String[] IP_DST_tmp;
    String[] IP_SRC_tmp;

    for (int i = 0; i < cap.jTable2.getRowCount(); i++) {
      String t_tmp_IP = cap.jTable2.getModel().getValueAt(i, 0).toString();

      if (t_tmp_IP.equals(Destination_IP) && destinyIs != false) {
        destinyIs = false;
      }

      if (t_tmp_IP.equals(Source_IP) && sourceIs != false) {
        sourceIs = false;
      }
    }

    IP_tmp = IP_adress.split("\\.");
    IP_DST_tmp = Destination_IP.split("\\.");
    IP_SRC_tmp = Source_IP.split("\\.");

    if (destinyIs) {

      cap.addIP(Destination_IP, Destination_MAC, "");
      if (isHeaderIPv4) {
        CheckDevice(Destination_IP, Source_IP);
        IPList.add(Destination_IP);
      }

      if (isHeaderIPv4 && IP_DST_tmp[2].equals(IP_tmp[2]) && IP_DST_tmp[1].equals(IP_tmp[1])) {
        moveRow++;
      }
    } else {
      for (int i = 0; i < DeviceList.size(); i++) {
        NetworkDevice tmp_device = DeviceList.get(i); 
        if (tmp_device != null && tmp_device.n_IP_Address.equals(Source_IP)) {
          int tmp_y = 0;
          for (int y = 0; y < DeviceList.size(); y++) {
            NetworkDevice tmp_dev = DeviceList.get(y); //dodat try
            if (tmp_dev != null && tmp_dev.n_IP_Address.equals(Destination_IP)) {
              tmp_y = y;
            }
            NetworkDevice tmp_dev_d = DeviceList.get(tmp_y);
            if (tmp_dev_d != null) {
              tmp_device.IPtime -= 100;
              tmp_device.destiny_xPosition = tmp_dev_d.n_xPosition;
              tmp_device.destiny_yPosition = tmp_dev_d.n_yPosition;
              if (tmp_device.IPtime < 0) tmp_device.IPtime = 0;
            }
          }
        }
      }
    }

    if (sourceIs) {
      cap.addIP(Source_IP, Source_MAC, "");
      if (isHeaderIPv4) {
        CheckDevice(Source_IP, Destination_IP);
        IPList.add(Source_IP);
      }
      if (isHeaderIPv4 && IP_SRC_tmp[2].equals(IP_tmp[2]) && IP_SRC_tmp[1].equals(IP_tmp[1])) {
        moveRow++;
      }
    } else {
      for (int i = 0; i < DeviceList.size(); i++) {
        NetworkDevice tmp_device = DeviceList.get(i);  
        if (tmp_device != null && tmp_device.n_IP_Address.equals(Destination_IP)) {
          int tmp_y = 0;
          for (int y = 0; y < DeviceList.size(); y++) {
            NetworkDevice tmp_dev = DeviceList.get(y);
            if (tmp_dev != null && tmp_dev.n_IP_Address.equals(Source_IP)) {
              tmp_y = y;
            }
            NetworkDevice tmp_dev_d = DeviceList.get(tmp_y);

            if (tmp_dev_d != null) {
              tmp_device.IPtime -= 100;
              tmp_device.destiny_xPosition = tmp_dev_d.n_xPosition;
              tmp_device.destiny_yPosition = tmp_dev_d.n_yPosition;
              if (tmp_device.IPtime < 0) tmp_device.IPtime = 0;
            }
          }
        }
      }
    }

    boolean praavda = true;
    boolean praavda2 = true;

    for (int i = 0; i < DeviceList.size(); i++) {
      NetworkDevice tmp_device = DeviceList.get(i); 
      if (tmp_device != null && tmp_device.n_IP_Address.equals(Source_IP)) {
        praavda = false;
      } 

      if (tmp_device != null && tmp_device.n_IP_Address.equals(Destination_IP)) {
        praavda2 = false;
      }
    }
    if (praavda && isHeaderIPv4) {

      CheckDevice(Source_IP, Destination_IP);
    }
    if (praavda2 && isHeaderIPv4) {

      CheckDevice(Destination_IP, Source_IP);
    }

    for (int i = 0; i < cap.jTable2.getRowCount(); i++) {

      String t_tmp_IP = cap.jTable2.getModel().getValueAt(i, 0).toString();
      String t_tmp_bytes = cap.jTable2.getModel().getValueAt(i, 2).toString();
      String[] tmp_bytes = t_tmp_bytes.split("/");

      if (t_tmp_IP.equals(Destination_IP) /*&& !t_tmp_IP.equals(IP_adress)*/) {
        double tmp_float = Float.parseFloat(tmp_bytes[1]);
        tmp_float = tmp_float + sizeofPacket;
        String tmp = tmp_bytes[0] + "/" + tmp_float;
        cap.jTable2.getModel().setValueAt(tmp, i, 2);
      }
      if (t_tmp_IP.equals(Source_IP) /*&& !t_tmp_IP.equals(IP_adress)*/) {
        double tmp_float = Float.parseFloat(tmp_bytes[0]);
        tmp_float = tmp_float + sizeofPacket;
        String tmp = tmp_float + "/" + tmp_bytes[1];
        cap.jTable2.getModel().setValueAt(tmp, i, 2);
      }
    }
  }
  public String[] getTime(PcapPacket Packet) {

    String timeStamp = new SimpleDateFormat("HH:mm:ss").format(Packet.getCaptureHeader().timestampInMillis());
    String[] time_fields = timeStamp.split(":");

    return time_fields;
  }
  @Override
    public void run() {

    //writer = new PrintWriter("paketky.txt", "UTF-8");

    PcapPacketHandler<String> jpacketHandler;
    jpacketHandler = new PcapPacketHandler<String>() {

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
      byte[] payloadContent;
      String file_name = sketchPath() + "\\day.cap";
      PcapDumper file_dumper = pcap.dumpOpen(file_name);
      int tmp_int = 0;

      public void nextPacket(PcapPacket packet, String user) {

        String ofile = sketchPath() + "\\data\\data" + IDs + ".cap";
        PcapDumper dumper = pcap.dumpOpen(ofile);

        byte[] IP_Destination = new byte[4];
        byte[] IP_Source = new byte[4];
        byte[] MAC_Source = new byte[4];
        byte[] MAC_Destination = new byte[4];
        int Port_Destination = 0;
        int Port_Source = 0;
        String Str_IP_Destination = "";
        String Str_IP_Source = "";
        String Str_MAC_Source = "";
        String Str_MAC_Destination = "";
        int sizeOfPacket = packet.getTotalSize();

        if (packet.hasHeader(eth)) {
          MAC_Source = packet.getHeader(eth).source();
          MAC_Destination = packet.getHeader(eth).destination();
          Str_MAC_Source = org.jnetpcap.packet.format.FormatUtils.mac(MAC_Source);
          Str_MAC_Destination = org.jnetpcap.packet.format.FormatUtils.mac(MAC_Destination);
        }
        /////////////////////////////////////////     IP    ///////////////////////////////////////////////////////////////////
        if (packet.hasHeader(ip)) {

          IP_Destination = packet.getHeader(ip).destination();
          IP_Source = packet.getHeader(ip).source();

          Str_IP_Destination = org.jnetpcap.packet.format.FormatUtils.ip(IP_Destination);
          Str_IP_Source = org.jnetpcap.packet.format.FormatUtils.ip(IP_Source);

          if (packet.hasHeader(tcp)) {

            Port_Destination = tcp.destination();
            Port_Source = tcp.source();
            if (packet.hasHeader(http)) {


              m_log = new Log(IDs, "HTTP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, http.fieldValue(Http.Request.Host));
              cap.addString(m_log);
              if (http.fieldValue(Http.Request.Host) != null)
                urllist.listModel.add(0, new Date() + ":  " + http.fieldValue(Http.Request.Host) + http.fieldValue(Http.Request.RequestUrl));
            } else {

              m_log = new Log(IDs, "TCP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "");
              cap.addString(m_log);
            }

            secApplet.traffic[tmp_int] = new packet_traffic(0, packet.size());
          } else if (packet.hasHeader(udp)) {


            Port_Destination = udp.destination();
            Port_Source = udp.source();

            if (packet.hasHeader(payload)) {
              m_log = new Log(IDs, "UDP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "DATA");
              cap.addString(m_log);
            } else if (packet.hasHeader(sip)) {

              m_log = new Log(IDs, "SIP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "");
              cap.addString(m_log);
              secApplet.traffic[tmp_int] = new packet_traffic(5, packet.size());
            } else {
              m_log = new Log(IDs, "UDP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "NO DATA");
              cap.addString(m_log);
            }
            secApplet.traffic[tmp_int] = new packet_traffic(1, packet.size());
          } else {

            m_log = new Log(IDs, "IP-OTHER", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "");
            cap.addString(m_log);
            secApplet.traffic[tmp_int] = new packet_traffic(5, packet.size());
          }

          CheckIP(Str_IP_Source, Str_IP_Destination, Str_MAC_Source, Str_MAC_Destination, true, sizeOfPacket);
          cap.addPort(Port_Source);
          cap.addPort(Port_Destination);
        } //////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

        else if (packet.hasHeader(icmp)) {
          m_log = new Log(IDs, "ICMP", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "Typ: " + icmp.type());
          cap.addString(m_log);
          CheckIP(Str_IP_Source, Str_IP_Destination, Str_MAC_Source, Str_MAC_Destination, true, sizeOfPacket);
          secApplet.traffic[tmp_int] = new packet_traffic(2, packet.size());
        } else if (packet.hasHeader(arp)) {
          m_log = new Log(IDs, "ARP", new Date().toString(), FormatUtils.ip(arp.spa()), Port_Source, FormatUtils.ip(arp.tpa()), Port_Destination, arp.operationDescription());
          cap.addString(m_log);
          secApplet.traffic[tmp_int] = new packet_traffic(3, packet.size());
          CheckIP(FormatUtils.ip(arp.spa()), FormatUtils.ip(arp.tpa()), Str_MAC_Source, Str_MAC_Destination, true, sizeOfPacket);
        } else if (packet.hasHeader(ip6)) {

          IP_Destination = packet.getHeader(ip6).destination();
          IP_Source = packet.getHeader(ip6).source();

          Str_IP_Destination = org.jnetpcap.packet.format.FormatUtils.ip(IP_Destination);
          Str_IP_Source = org.jnetpcap.packet.format.FormatUtils.ip(IP_Source);

          if (packet.hasHeader(tcp)) {
            Port_Destination = tcp.destination();
            Port_Source = tcp.source();
            m_log = new Log(IDs, "TCP-IPv6", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "");
            cap.addString(m_log);
          } else if (packet.hasHeader(udp)) {
            Port_Destination = udp.destination();
            Port_Source = udp.source();
            m_log = new Log(IDs, "UDP-IPv6", new Date().toString(), Str_IP_Source, Port_Source, Str_IP_Destination, Port_Destination, "");
            cap.addString(m_log);
          } else {

            m_log = new Log(IDs, "OTHER-IPv6", new Date().toString(), Str_IP_Source, 0, Str_IP_Destination, 0, "DATA");
            cap.addString(m_log);
          }
          CheckIP(Str_IP_Source, Str_IP_Destination, Str_MAC_Source, Str_MAC_Destination, false, sizeOfPacket);
          secApplet.traffic[tmp_int] = new packet_traffic(4, packet.size());
        } else {
          /*    println(packet.getFlowKey().getHeaderMap());
           println(packet.getHeader(ieee2, 0));
           println(packet.getHeader(ieee2, 2));
           println(packet.getCaptureHeader());
           println(packet.toDebugString());
           println(packet.toHexdump());
           println(packet.getHeaderCount());
           println(JRegistry.toDebugString());*/

          if (packet.hasHeader(ieee2)) {
            m_log = new Log(IDs, "LLC", new Date().toString(), Str_IP_Source, 0, Str_IP_Destination, 0, "");
            cap.addString(m_log);
          }

          if (packet.hasHeader(ieee3)) {
            System.out.println("iiieee3");
          }
          if (packet.hasHeader(ieees)) {
            System.out.println("iiieees");
          }

          if (packet.hasHeader(sdp)) {
            System.out.println("iisdp");
          }
          if (packet.hasHeader(rtp)) {
            System.out.println("iirtp");
          }
          if (packet.hasHeader(ppp)) {
            System.out.println("iippp");
          }
          if (packet.hasHeader(l2tp)) {
            System.out.println("iil2tp");
          }
          if (packet.hasHeader(sll)) {
            System.out.println("iisll");
          }


          secApplet.traffic[tmp_int] = new packet_traffic(5, packet.size());
        }

        total_bytes += sizeOfPacket;
        //System.out.println(total_bytes);
        IDs++;

        if (tmp_counter_packets == 244999) {
        } else tmp_counter_packets++;

        if (tmp_int == 244999) tmp_int = 0;
        else tmp_int++;

        dumper.dump(packet);
        //file_dumper.dump(packet);
        dumper.close();
      }
    };

    pcap.loop(pcap.LOOP_INFINITE, jpacketHandler, 
      "");

    pcap.close();
  }
}