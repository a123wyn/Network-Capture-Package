package com.nic.show;
import java.awt.*;
import java.awt.event.*;
import java.io.FileOutputStream;
import java.io.File;
import java.util.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import jpcap.JpcapCaptor;
import jpcap.NetworkInterface;
import jpcap.packet.IPPacket;
import jpcap.packet.ARPPacket;
import jpcap.packet.Packet;
import com.nic.control.PacketCapture;
import com.nic.control.PacketAnalyze;
import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;


public class MyInterface extends JFrame{ //用JFrame框架进行可视化处理
	JMenuBar menuBar; //菜单条
	JMenu cardmenu,savemenu; //网卡菜单 保存菜单
	JTextField searchText; //表示搜索文本框
	JMenuItem cardItems,saveItem1,saveItem2; //表示网卡的菜单项的变量 保存菜单项变量
	JLabel label; //表示标签
	JButton okButton; //确认按钮
	JButton startButton,stopButton; //开始结束按钮
	JPanel panel; //面板
	JScrollPane scrollPane; //滚动轴
	JTable table; //表格
	final String[] head = new String[] {
			"No.","Time","Source", "Destination", "Protocol", "Length"
	}; //表格标题
	NetworkInterface[] devices; //网卡信息
	Object[][] dataList = {}; //二维数组表示表格信息
	DefaultTableModel defaultModel; //创建表格模型
	PacketCapture packetCaptor; //抓包
	Thread thread;
	public MyInterface(){ //构造函数
		this.setTitle("MySniffer"); //界面的标题
		this.setBounds(200, 200, 500, 800); //设置窗口边框参数
		this.setLocationRelativeTo(null); //将窗口置于屏幕中央
		//选择网卡进行过滤
		packetCaptor = new PacketCapture(); //抓包
		menuBar = new JMenuBar(); //菜单条
		cardmenu = new JMenu(" NetworkCard:  "); //网卡菜单
		devices = JpcapCaptor.getDeviceList(); //获得所有网卡信息
		for (int i = 0; i < devices.length; i++) {
			cardItems = new JMenuItem( i + "/name: " + devices[i].name + "("
					+ devices[i].description  + ")"); //网卡的菜单项变量
			cardmenu.add(cardItems); //将菜单项添加到网卡菜单
			cardItems.addActionListener( //每个网卡都添加事件监听器，随时对事件源进行响应
					new CardActionListener(devices[i])
			); //监听器响应鼠标点击，并开启对应网卡的抓包线程
		}
		//开始按钮
		startButton = new JButton("  Start:    ");
		startButton.addMouseListener( //添加鼠标监听器
				new MouseAdapter(){
					public void mouseClicked(MouseEvent e) { //鼠标点击
						while(defaultModel.getRowCount()>0) { //获取表格行的数量
							defaultModel.removeRow(defaultModel.getRowCount() - 1); //开始时删除所有抓包信息
						}
						packetCaptor.clearpackets(); //删除packetCaptor列表信息
						thread = new Thread(packetCaptor);
						thread.start(); //开启抓包线程
					}
				});
		//保存数据包
		savemenu = new JMenu(" Save  ");
		saveItem1 = new JMenuItem("Save all");
		saveItem2 = new JMenuItem("Save current");
		savemenu.add(saveItem1); //将菜单项添加
		savemenu.add(saveItem2); //将菜单项添加
		saveItem1.addActionListener( //添加事件监听器，随时对事件源进行响应
				new ActionListener(){
					public void actionPerformed(ActionEvent e) {
						JFileChooser chooser = new JFileChooser(); //文件导航窗口
						FileNameExtensionFilter filter = new FileNameExtensionFilter("纯文本(*.txt)", "txt"); //文件过滤器
						chooser.setFileFilter(filter); //设置默认的文件过滤器
						int returnVal = chooser.showSaveDialog(new JPanel()); //打开选择器面板
						if (returnVal == JFileChooser.APPROVE_OPTION) { //点击确认或保存
							String path = chooser.getSelectedFile().getPath(); //获取文件路径
							ArrayList<JTextArea> packetlist_content = packetCaptor.getpacketlist_content();
							String text="";
							for (int i = 0; i < packetlist_content.size(); i++) { //抓包的所有内容
								text = text+packetlist_content.get(i).getText();
							}
							try {
								File f = new File(path + ".txt");
								f.createNewFile(); //创建一个空的文件
								FileOutputStream out = new FileOutputStream(f);
								out.write(text.getBytes()); //写入文件
								out.close(); //关闭文件
							}
							catch (Exception e1) {
								e1.printStackTrace();
							}
						}
					}
				});
		saveItem2.addActionListener( //添加事件监听器，随时对事件源进行响应
				new ActionListener(){
					public void actionPerformed(ActionEvent e) {
						JFileChooser chooser = new JFileChooser(); //文件导航窗口
						FileNameExtensionFilter filter = new FileNameExtensionFilter("纯文本(*.txt)","txt"); //文件过滤器
						chooser.setFileFilter(filter); //设置默认的文件过滤器
						int returnVal = chooser.showSaveDialog(new JPanel()); //打开选择器面板
						if(returnVal == JFileChooser.APPROVE_OPTION) { //点击确认或保存
							String path = chooser.getSelectedFile().getPath(); //获取文件路径
							ArrayList<JTextArea> nowpacketlist_content = packetCaptor.getnowpacketlist_content();
							String text="";
							for (int i = 0; i < nowpacketlist_content.size(); i++) { //抓包的所有内容
								text = text+nowpacketlist_content.get(i).getText();
							}
							try {
								File f = new File(path + ".txt");
								f.createNewFile(); //创建一个空的文件
								FileOutputStream out = new FileOutputStream(f);
								out.write(text.getBytes()); //写入文件
								out.close(); //关闭文件
							}
							catch (Exception e1) {
								e1.printStackTrace();
							}
						}
					}
				});
		//停止按钮
		stopButton = new JButton(" Stop  ");
		stopButton.addMouseListener( //添加鼠标监听器
				new MouseAdapter(){
					public void mouseClicked(MouseEvent e) { //鼠标点击
						thread.stop(); //停止线程
					}
				});

		Container contentPane = getContentPane(); //返回JFrame窗体的内容对象
		contentPane.setLayout(new BorderLayout()); //用BorderLayout进行内容布局
		//将菜单以及按钮添加到菜单条上
		menuBar.add(cardmenu);
		menuBar.add(savemenu);
		menuBar.add(startButton);
		menuBar.add(stopButton);
		contentPane.add(menuBar,BorderLayout.NORTH); //菜单条加入到内容窗格中
		setLocationRelativeTo(null); //将窗口置于屏幕中央
		//设置过滤搜索框
		label = new JLabel("Please enter filter mess:"); //搜索框标题
		searchText = new JTextField(50); //指定搜索框列数
		searchText.setPreferredSize(new Dimension (50,1)); //设置搜索框大小
		okButton = new JButton("确定"); //确定按钮
		//搜索框加入到内容窗格中
		contentPane.add(label,BorderLayout.WEST);
		contentPane.add(searchText,BorderLayout.CENTER);
		contentPane.add(okButton,BorderLayout.EAST);
		okButton.addMouseListener( //添加鼠标监听器
				new MouseAdapter(){
					public void mouseClicked(MouseEvent e) { //鼠标点击
						String filter = searchText.getText(); //获取输入文本信息
						ArrayList<Packet> packetlist = packetCaptor.getpacketlist(); //抓包的总列表
						ArrayList<Packet> nowpacketlist = packetCaptor.getnowpacketlist(); //抓包的过滤列表
						ArrayList<JTextArea> nowpacketlist_content = packetCaptor.getnowpacketlist_content(); //抓包过滤列表的内容，用于保存
						nowpacketlist.clear(); //清空抓包的过滤列表
						nowpacketlist_content.clear(); //清空抓包过滤列表的内容
						//thread.suspend();
						packetCaptor.setFilter(filter); //设置过滤信息
						while(defaultModel.getRowCount()>0){ //获取表格行的数量
							defaultModel.removeRow(defaultModel.getRowCount()-1); //删除所有抓包信息
						}
						for(int i=0;i<packetlist.size();i++){
							Packet packet = packetlist.get(i); //获取抓包列表的每一行
							if(packet!=null&&packetCaptor.TestFilter(packet)){ //符合过滤条件
								String[] rowData = packetCaptor.getobj(packet,i+1); //将抓包的信息显示在列表上
								nowpacketlist.add(packet); //加入到过滤列表
								nowpacketlist_content.add(packetCaptor.getinfo(packet)); //将具体信息加入过滤列表的内容
								defaultModel.addRow(rowData); //表格模型添加一行
							}
						}
						//thread.resume();
					}
				});
		defaultModel = new DefaultTableModel(dataList, head); //表格模型，设置数据和表头
		table = new JTable(defaultModel){ //创建表格并使表格模型与之关联
			public boolean isCellEditable(int row, int column){
				return false;
			}
		};
		packetCaptor.setTable(defaultModel); //包的信息显示在表格中
		table.setPreferredScrollableViewportSize(new Dimension(500, 500)); //设置表格大小
		table.setRowHeight(30); //设置每行高度为30
		table.setRowMargin(5); //设置相邻两行单元格的距离
		table.setRowSelectionAllowed(true); //设置可否被选择.默认为false
		table.setSelectionBackground(Color.cyan); //设置所选择行的背景色
		table.setSelectionForeground(Color.red); //设置所选择行的前景色
		table.setShowGrid(true); //是否显示网格线
		//table.doLayout();
		scrollPane = new JScrollPane(table); //添加表格到滚动轴
		panel = new JPanel(new GridLayout(0, 1)); //创建面板
		panel.setPreferredSize(new Dimension(500, 500)); //设置面板大小
		panel.setBackground(Color.black); //设置背景色
		panel.add(scrollPane); //添加滚动轴到面板上
		contentPane.add(panel,BorderLayout.SOUTH); //面板添加到窗口
		pack(); //调整窗口大小使其适应布局

		table.addMouseListener(new MouseAdapter(){ //添加鼠标监听器
			public void mouseClicked(MouseEvent e){
				if(e.getClickCount() == 2){ //鼠标对表格双击的处理事件
					int row = table.getSelectedRow(); //获取表格行号
					JFrame frame = new JFrame("More Information"); //创建一个新的窗口
					JPanel panel = new JPanel(); //创建新的面板
					ArrayList<JTextArea> nowpacketlist_content = packetCaptor.getnowpacketlist_content();
					final JTextArea info = nowpacketlist_content.get(row); //默认可见行数
					info.setEditable(false); //文本是否可编辑
					info.setLineWrap(true); //是否自动换行
					info.setWrapStyleWord(true); //自动换行方式
					frame.add(panel); //面板添加到窗口
					panel.add(new JScrollPane(info));  //添加滚动轴到面板
					JButton save = new JButton("Save as"); //保存按钮

					save.addActionListener( //添加事件监听器，随时对事件源进行响应
							new ActionListener(){
								public void actionPerformed(ActionEvent e3) {
									JFileChooser chooser = new JFileChooser(); //文件导航窗口
									FileNameExtensionFilter filter = new FileNameExtensionFilter("纯文本(*.txt)","txt"); //文件过滤器
									chooser.setFileFilter(filter); //设置默认的文件过滤器
									int returnVal = chooser.showSaveDialog(new JPanel()); //打开选择器面板
									if(returnVal == JFileChooser.APPROVE_OPTION) { //点击确认或保存
										String path = chooser.getSelectedFile().getPath(); //获取文件路径
										String text = info.getText();
										try {
											File f = new File(path+".txt");
											//System.out.println(f.getAbsolutePath());
											f.createNewFile(); //创建一个空的文件
											FileOutputStream out = new FileOutputStream(f);
											out.write(text.getBytes()); //写入文件
											out.close(); //关闭文件
										}
										catch (Exception e) {
											e.printStackTrace();
										}
									}
								}
							});
					panel.add(save); //添加按钮到面板
					frame.setBounds(150, 150, 500, 500); //窗体大小设置
					frame.setVisible(true); //窗体显示
					frame.setResizable(false); //窗体是否允许用户调整大小
				}
			}
		});
		setResizable(false);
		setVisible(true);
		addWindowListener(new WindowAdapter() {
			public void windowClosing(WindowEvent e) {
				System.exit(0);
			}
		});

	}

	private class CardActionListener implements ActionListener{ //用于监听事件源的监听器
		NetworkInterface device;
		CardActionListener(NetworkInterface device){ //构造函数中的参数即为需要抓包的网卡
			this.device = device;
		}
		public void actionPerformed(ActionEvent e) { //响应的事件处理函数
			packetCaptor.setDevice(device); //抓包类的网卡设置
			packetCaptor.setFilter(""); //过滤信息
		}
	}
}