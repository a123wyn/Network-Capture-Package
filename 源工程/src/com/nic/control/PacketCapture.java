package com.nic.control;
import java.io.IOException;
import java.text.*;
import java.util.*;
import javax.swing.*;
import javax.swing.table.*;
import jpcap.*;
import jpcap.packet.*;

//抓包线程
public class PacketCapture implements Runnable {	//继承runnable接口
	int index;//包的编号
	NetworkInterface device;//抓包设备
	DefaultTableModel tablemodel;//表格模型
	String filtermess = "";//初始化过滤规则
	ArrayList<Packet> packetlist = new ArrayList<Packet>();//抓包的总列表
    ArrayList<Packet> nowpacketlist = new ArrayList<Packet>();//抓包的过滤列表
    ArrayList<JTextArea> packetlist_content = new ArrayList<JTextArea>();//抓包总列表的内容，用于保存
    ArrayList<JTextArea> nowpacketlist_content = new ArrayList<JTextArea>();//抓包过滤列表的内容，用于保存
	public PacketCapture() {
	}
	public void setDevice(NetworkInterface device){//设置设备
		this.device = device;
	}
	public void setTable(DefaultTableModel tablemodel){//设置表格模型
		this.tablemodel = tablemodel;
	}
	public void setFilter(String filtermess){//设置过滤规则
		this.filtermess = filtermess;
	}
	public void clearpackets(){//清除各个项目
		packetlist.clear();
		nowpacketlist.clear();
		packetlist_content.clear();
		nowpacketlist_content.clear();
	}
	@Override
	public void run() {
		// TODO Auto-generated method stub
		index = 0;//初始化包的编号为1
		Packet packet;//捕获到的包
		try {
			JpcapCaptor captor = JpcapCaptor.openDevice(device, 65535,true, 20);//第二个参数表示一次捕获数据包的最大byte数，最后一个表示超时设置参数
																										//第三个参数决定是否采用混乱模式
																										//混乱模式中，可以捕获所有数据包，即便源MAC或目的MAC地址与打开的网络接口的MAC地址不相同。
																										//而非混乱模式中只能捕获由宿主机发送和接收的数据包
			while(true){
				//long startTime = System.currentTimeMillis();
				while (true) {//代码执行效率
					packet = captor.getPacket();//抓住一个包
					//设置过滤器
					String filter = filtermess;
					setFilter("");
					if(packet!=null&&TestFilter(packet)) {//默认的抓四个协议的全部包到总包列表中
						packetlist.add(packet);//在总包的列表中添加，总包的列表存的是当前抓的所有的包
						packetlist_content.add(getinfo(packet));//包的内容列表中也同步添加，内容列表影响到展示在表格上的信息
						index++;//每捕捉到四个协议中的包，则序号增加，用于下次抓的包
						setFilter(filter);
						if (TestFilter(packet)) {//设置的过滤规则
							nowpacketlist.add(packet);//这个数组反映的是当前展示在表格中的包，注意与总包的列表进行区分，它会随着过滤规则的变化而不断变化着
							nowpacketlist_content.add(getinfo(packet));//这个数组是当前展示在表格中的包的内容信息
							showTable(packet);//将包的内容信息打印在表格中
						}
					}
					Thread.sleep(400);//暂停400ms
				}
//				synchronized(this) {
//					while (suspended) {
//						wait();
//					}
//				}
			}
		}
		catch (IOException e) {
			e.printStackTrace();
		}
		catch (InterruptedException e) {
			e.printStackTrace();
		}	
	}
//	public void suspend(){
//		suspended = true;
//	}
//	synchronized void resume(){
//		suspended = false;
//		notify();
//	}
	//将符合过滤规则抓到的包以可视化的形式在表格上显示出来，具体显示些什么在getobj函数中有具体实现
	public void showTable(Packet packet){
		String[] rowData = getobj(packet,index);//摘录下的信息，以字符串数组形式返回
		tablemodel.addRow(rowData);//代表信息添加到表格中
	}
	//通过抓的包获取内容具体信息，返回的是JTextArea类，直接添加进可视化框架中
	public JTextArea getinfo(Packet packet){
        JTextArea info = new JTextArea(23, 42);
        info.setEditable(false);//文本是否可编辑
        info.setLineWrap(true);//是否自动换行
        info.setWrapStyleWord(true);//自动换行方式
        LinkedHashMap<String,String> hm0;
        LinkedHashMap<String,String> hm1;
        LinkedHashMap<String,String> hm2;
        hm0 = new PacketAnalyze(packet).Ethernetanalyze();//物理头的内容信息
        info.append("------------------------------------------------------------------------------\n");
        info.append("-------------------------------ETH头信息-------------------------------\n");
        info.append("------------------------------------------------------------------------------\n");
        for(Map.Entry<String,String> me0 : hm0.entrySet())
        {
            info.append(me0.getKey()+" : "+me0.getValue()+"\n");
        }
        hm1 = new PacketAnalyze(packet).packetClass();//ip/arp头的内容信息
        info.append("------------------------------------------------------------------------------\n");
        info.append("-------------------------------"+hm1.get("")+"头信息-------------------------------\n");
        info.append("------------------------------------------------------------------------------\n");
        for(Map.Entry<String,String> me1 : hm1.entrySet())
        {
            if(packet instanceof IPPacket){
                if(me1.getKey()!=""){
                    info.append(me1.getKey()+" : "+me1.getValue()+"\n");
                }
            }
            else{
                if(me1.getKey()!=""&&me1.getKey()!="Protocol"){//每个包内容分析中都有Protocol字段，这是为了摘录包信息方便而用的，在分析首部时不用打印出来
                    info.append(me1.getKey()+" : "+me1.getValue()+"\n");
                }
            }
        }
        if(packet instanceof IPPacket){//如果是ip头则下面还有三个协议，icmp，tcp，udp，继续打印头部信息
            hm2 = new PacketAnalyze(packet).IPPacketClass();
            info.append("------------------------------------------------------------------------------\n");
            info.append("-----------------------------"+hm2.get("Protocol")+"头信息-----------------------------\n");
            info.append("------------------------------------------------------------------------------\n");
            for(Map.Entry<String,String> me : hm2.entrySet())
            {
                if(me.getKey()!=""&&me.getKey()!="Protocol"){//与上面的解释相同
                    info.append(me.getKey()+" : "+me.getValue()+"\n");
                }
            }
        }
        return info;
    }
	//其他类通过此方法获取总包的列表
	public ArrayList<Packet> getpacketlist(){
		return packetlist;
	}
	//其他类通过此方法获取当前过滤规则下包的列表
    public ArrayList<Packet> getnowpacketlist(){
        return nowpacketlist;
    }
	//其他类通过此方法获取总包内容的列表
    public ArrayList<JTextArea> getnowpacketlist_content(){
        return nowpacketlist_content;
    }
	//其他类通过此方法获取当前过滤规则下的包内容信息列表
    public ArrayList<JTextArea> getpacketlist_content(){
        return packetlist_content;
    }
	//将符合过滤信息的包筛选出来，过滤规则就是本类的filtermess成员变量，符合的返回true，不符合的返回false
	public boolean TestFilter(Packet packet){
		if(filtermess.contains("!")){//非运算的过滤
			int Filtermess_start= filtermess.indexOf("!")+2;
			int Filtermess_end= filtermess.indexOf(")");
			String Filtermess= filtermess.substring(Filtermess_start,Filtermess_end);
			PacketCapture captor1=new PacketCapture();
			captor1.setFilter(Filtermess);
			if(!captor1.TestFilter(packet)){
				if((Filtermess_start-2)==0&&(Filtermess_end+1)== filtermess.length()){
					return true;
				}
				else if((Filtermess_start-2)==0){
					String symbol2= filtermess.substring(Filtermess_end+1,Filtermess_end+3);
					if(symbol2.equals("&&")){
						String filtermess= this.filtermess.substring(Filtermess_end+3, this.filtermess.length());
						PacketCapture captor2=new PacketCapture();
						captor2.setFilter(filtermess);
						if(captor2.TestFilter(packet)){
							return true;
						}
					}
					else if(symbol2.equals("||")){
						return true;
					}
				}
				else if((Filtermess_end+1)== filtermess.length()){
					String symbol1= filtermess.substring(Filtermess_start-4,Filtermess_start-2);
					if(symbol1.equals("&&")){
						String filtermess= this.filtermess.substring(0,Filtermess_start-4);
						PacketCapture captor2=new PacketCapture();
						captor2.setFilter(filtermess);
						if(captor2.TestFilter(packet)){
							return true;
						}
					}
					else if(symbol1.equals("||")){
						return true;
					}
				}
			}
			else{
				if((Filtermess_start-2)==0&&(Filtermess_end+1)== filtermess.length()){
					return false;
				}
				if((Filtermess_start-2)==0){
					String symbol2= filtermess.substring(Filtermess_end+1,Filtermess_end+3);
					if(symbol2.equals("||")){
						String filtermess= this.filtermess.substring(Filtermess_end+3, this.filtermess.length());
						PacketCapture captor2=new PacketCapture();
						captor2.setFilter(filtermess);
						if(captor2.TestFilter(packet)){
							return true;
						}
					}
				}
				else if((Filtermess_end+1)== filtermess.length()){
					String symbol1= filtermess.substring(Filtermess_start-4,Filtermess_start-2);
					if(symbol1.equals("||")){
						String filtermess= this.filtermess.substring(0,Filtermess_start-4);
						PacketCapture captor2=new PacketCapture();
						captor2.setFilter(filtermess);
						if(captor2.TestFilter(packet)){
							return true;
						}
					}
				}
			}
		}
		else if(filtermess.contains("&&")){//与运算的过滤
			int Filtermess1_end= filtermess.indexOf("&&");
			int Filtermess2_start=Filtermess1_end+2;
			String Filtermess1= filtermess.substring(0,Filtermess1_end);
			String Filtermess2= filtermess.substring(Filtermess2_start, filtermess.length());
			PacketCapture captor1=new PacketCapture();
			captor1.setFilter(Filtermess1);
			PacketCapture captor2=new PacketCapture();
			captor2.setFilter(Filtermess2);
			if(captor1.TestFilter(packet)&&captor2.TestFilter(packet)){
				return true;
			}
		}
		else if(filtermess.contains("||")) {//或运算的过滤
			int Filtermess1_end= filtermess.indexOf("||");
			int Filtermess2_start=Filtermess1_end+2;
			String Filtermess1= filtermess.substring(0,Filtermess1_end);
			String Filtermess2= filtermess.substring(Filtermess2_start, filtermess.length());
			PacketCapture captor1=new PacketCapture();
			captor1.setFilter(Filtermess1);
			PacketCapture captor2=new PacketCapture();
			captor2.setFilter(Filtermess2);
			if(captor1.TestFilter(packet)||captor2.TestFilter(packet)){
				return true;
			}
		}
		else{
			//frame长度过滤
			if(filtermess.contains("frame")){
				if(filtermess.substring(6,9).equals("len")){
					String len= filtermess.substring(13, filtermess.length());
					String symbol= filtermess.substring(10,12);
					if(symbol.equals("==")){
						if(packet.len==Integer.parseInt(len)){
							return true;
						}
					}
					else if(symbol.equals(">=")){
						if(packet.len>=Integer.parseInt(len)){
							return true;
						}
					}
					else if(symbol.equals("<=")){
						if(packet.len<=Integer.parseInt(len)){
							return true;
						}
					}
				}
			}
			//eth过滤
			else if(filtermess.contains("eth")){
				if(filtermess.substring(4,8).equals("addr")){
					String addr= filtermess.substring(12, filtermess.length());
					EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
					if(ethernetPacket.getSourceAddress().equals(addr)||ethernetPacket.getDestinationAddress().equals(addr)){
						return true;
					}
				}
				else if(filtermess.substring(4,7).equals("src")){
					String s= filtermess.substring(11, filtermess.length());
					EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
					if(ethernetPacket.getSourceAddress().equals(s)){
						return true;
					}
				}
				else if(filtermess.substring(4,7).equals("dst")){
					String d= filtermess.substring(11, filtermess.length());
					EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;
					if(ethernetPacket.getDestinationAddress().equals(d)){
						return true;
					}
				}
			}
			//ip过滤
			else if(filtermess.contains("ip")){
				if(packet instanceof IPPacket)
				{
					if(filtermess.length() == 2){
						return true;
					}
					else if(filtermess.substring(3,7).equals("addr")){
						String addr= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(analyze.IPanalyze().get("Source").equals(addr)||analyze.IPanalyze().get("Destination").equals(addr)){
							return true;
						}
					}
					else if(filtermess.substring(3,6).equals("src")){
						String sip= filtermess.substring(10, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(analyze.IPanalyze().get("Source").equals(sip)){
							return true;
						}
					}
					else if(filtermess.substring(3,6).equals("dst")){
						String dip= filtermess.substring(10, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(analyze.IPanalyze().get("Destination").equals(dip)){
							return true;
						}
					}
					else if(filtermess.substring(3,6).equals("len")){
						String len= filtermess.substring(10, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						String symbol= filtermess.substring(7,9);
						if(symbol.equals("==")){
							if(analyze.IPanalyze().get("Total Length").equals(len)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							int length=Integer.parseInt(analyze.IPanalyze().get("Total Length"));
							if(length>=Integer.parseInt(len)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							int length=Integer.parseInt(analyze.IPanalyze().get("Total Length"));
							if(length<=Integer.parseInt(len)){
								return true;
							}
						}
					}
				}
			}
			//icmp过滤
			else if(filtermess.contains("icmp")){
				if(packet.getClass().equals(ICMPPacket.class)){
					if(filtermess.length() == 4){
						return true;
					}
					else if(filtermess.substring(5,9).equals("type")){
					    String type= filtermess.substring(13, filtermess.length());
                        PacketAnalyze analyze = new PacketAnalyze(packet);
                        if(analyze.IPPacketClass().get("Type").equals(type)){
                            return true;
                        }
                    }
				}

			}
			//tcp过滤
			else if(filtermess.contains("tcp")){
				if(packet.getClass().equals(TCPPacket.class)){
					if(filtermess.length() == 3){
						return true;
					}
					else if(filtermess.substring(4,8).equals("port")){
						String port= filtermess.substring(12, filtermess.length());
						String symbol = filtermess.substring(9,11);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Source Port").equals(port)||analyze.IPPacketClass().get("Destination Port").equals(port)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))<=Integer.parseInt(port)||Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))<=Integer.parseInt(port)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))>=Integer.parseInt(port)||Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))>=Integer.parseInt(port)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,11).equals("srcport")){
						String sport= filtermess.substring(15, filtermess.length());
						String symbol = filtermess.substring(12,14);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Source Port").equals(sport)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))<=Integer.parseInt(sport)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))>=Integer.parseInt(sport)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,11).equals("dstport")){
						String dport= filtermess.substring(15, filtermess.length());
						String symbol = filtermess.substring(12,14);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Destination Port").equals(dport)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))<=Integer.parseInt(dport)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))>=Integer.parseInt(dport)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("syn")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Syn Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Syn Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("fin")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Fin Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Fin Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("urg")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Urgent Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Urgent Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("ack")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Ack Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Ack Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("psh")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Push Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Push Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("rst")){
						String syn= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(syn.equals("0")){
							if(analyze.IPPacketClass().get("Reset Flag").equals("false")){
								return true;
							}
						}
						else{
							if(analyze.IPPacketClass().get("Reset Flag").equals("true")){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("len")){
						String len= filtermess.substring(11, filtermess.length());
						TCPPacket tcppacket=(TCPPacket)packet;
						PacketAnalyze analyze=new PacketAnalyze(packet);
						int tcphead=Integer.parseInt(analyze.TCPanalyze().get("Head length"));
						String symbol= filtermess.substring(8,10);
						int datalen=tcppacket.data.length+tcphead;
						if(symbol.equals("==")){
							if(datalen == Integer.parseInt(len)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(datalen>=Integer.parseInt(len)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(datalen<=Integer.parseInt(len)){
								return true;
							}
						}
					}
				}
			}
			//udp过滤
			else if(filtermess.contains("udp")){
				if(packet.getClass().equals(UDPPacket.class)){
					if(filtermess.length() == 3){
						return true;
					}
					else if(filtermess.substring(4,8).equals("port")){
						String port= filtermess.substring(12, filtermess.length());
						String symbol = filtermess.substring(9,11);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Source Port").equals(port)||analyze.IPPacketClass().get("Destination Port").equals(port)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))<=Integer.parseInt(port)||Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))<=Integer.parseInt(port)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))>=Integer.parseInt(port)||Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))>=Integer.parseInt(port)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,11).equals("srcport")){
						String sport= filtermess.substring(15, filtermess.length());
						String symbol = filtermess.substring(12,14);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Source Port").equals(sport)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))<=Integer.parseInt(sport)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Source Port"))>=Integer.parseInt(sport)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,11).equals("dstport")){
						String dport= filtermess.substring(15, filtermess.length());
						String symbol = filtermess.substring(12,14);
						PacketAnalyze analyze = new PacketAnalyze(packet);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Destination Port").equals(dport)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))<=Integer.parseInt(dport)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							if(Integer.parseInt(analyze.IPPacketClass().get("Destination Port"))>=Integer.parseInt(dport)){
								return true;
							}
						}
					}
					else if(filtermess.substring(4,7).equals("len")){
						String len= filtermess.substring(11, filtermess.length());
						PacketAnalyze analyze = new PacketAnalyze(packet);
						String symbol= filtermess.substring(8,10);
						if(symbol.equals("==")){
							if(analyze.IPPacketClass().get("Length").equals(len)){
								return true;
							}
						}
						else if(symbol.equals(">=")){
							int length=Integer.parseInt(analyze.IPPacketClass().get("Length"));
							if(length>=Integer.parseInt(len)){
								return true;
							}
						}
						else if(symbol.equals("<=")){
							int length=Integer.parseInt(analyze.IPPacketClass().get("Length"));
							if(length<=Integer.parseInt(len)){
								return true;
							}
						}
					}
				}
			}
			//arp过滤
            else if(filtermess.contains("arp")){
                if(packet.getClass().equals(ARPPacket.class)){
                    if(filtermess.length()==3){
                        return true;
                    }
                    else if(filtermess.substring(4,8).equals("addr")){
                        String addr= filtermess.substring(12, filtermess.length());
                        PacketAnalyze analyze = new PacketAnalyze(packet);
                        if(analyze.ARPanalyze().get("Sender MAC address").equals(addr)||analyze.ARPanalyze().get("Target MAC address").equals(addr)){
                            return true;
                        }
                    }
                    else if(filtermess.substring(4,7).equals("src")){
                        String smac= filtermess.substring(11, filtermess.length());
                        PacketAnalyze analyze = new PacketAnalyze(packet);
                        if(analyze.ARPanalyze().get("Sender MAC address").equals(smac)){
                            return true;
                        }
                    }
                    else if(filtermess.substring(4,7).equals("dst")){
                        String dmac= filtermess.substring(11, filtermess.length());
                        PacketAnalyze analyze = new PacketAnalyze(packet);
                        if(analyze.ARPanalyze().get("Target MAC address").equals(dmac)){
                            return true;
                        }
                    }

                }
            }
            //无过滤规则则默认抓icmp、udp、tcp和arp四种协议报文
			else if(filtermess.equals("")){
				if(packet instanceof ICMPPacket)
					return true;
				if(packet instanceof ARPPacket)
					return true;
				if(packet instanceof IPPacket)
					return true;
				if(packet instanceof TCPPacket)
					return true;
				if(packet instanceof UDPPacket)
					return true;
			}
		}
		return false;//否则返回false
	}
	//摘录出当前抓的包的基本信息显示在列表上，返回信息是String[]字符串数组形式
	public static String[] getobj(Packet packet, int index){//index意思为包的编号
		String[] data = new String[6];
		PacketAnalyze analyze=new PacketAnalyze(packet);//调用PacketAnalyze类来分析包的内容以便于摘录出基本信息
		if (packet != null&&analyze.packetClass().size()>=3) {//若是空包则跳过
			Date d = new Date();
			DateFormat df = new SimpleDateFormat("HH:mm:ss");
			data[0]=String.valueOf(index);//包的编号
			data[1]=df.format(d);//时间
			data[2]=analyze.packetClass().get("Source");//源地址
			data[3]=analyze.packetClass().get("Destination");//目的地址
			data[4]=analyze.packetClass().get("Protocol");//协议类型，在打印包的内容信息时是不打印的
			data[5]=String.valueOf(packet.len);//整个包的长度
		}
		return data;
	}
}
