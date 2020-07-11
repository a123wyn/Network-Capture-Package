package com.nic.control;
import java.util.LinkedHashMap;
import jpcap.packet.*;


public class PacketAnalyze {
    static Packet packet;
    static LinkedHashMap<String,String> att,att1;
    public PacketAnalyze(Packet packet){
        this.packet = packet;
    }

    public static LinkedHashMap<String,String> IPPacketClass(){//对IP数据包里的具体数据类型判断
        att1 = new LinkedHashMap<>();//创建一个空的linked哈希表
        if(packet.getClass().equals(ICMPPacket.class)){//ICMP报文
            att1 = ICMPanalyze();
        }
        else if(packet.getClass().equals(TCPPacket.class)){//TCP报文
            att1 = TCPanalyze();
        }
        else if(packet.getClass().equals(UDPPacket.class)) {//UDP报文
            att1 = UDPanalyze();
        }
        return att;
    }
    public static LinkedHashMap<String,String> packetClass(){//不同类型的数据包
        att1 = new LinkedHashMap<>();
        if(packet.getClass().equals(ARPPacket.class)){//ARP数据
            att1 = ARPanalyze();
        }else if(packet instanceof IPPacket){//IP数据
            att1 = IPanalyze();
        }
        return att;
    }

    public static LinkedHashMap<String, String> Ethernetanalyze(){//物理头分析
        att = new LinkedHashMap<String, String>();
        if(packet instanceof IPPacket || packet instanceof ARPPacket){//判断类型
            EthernetPacket ethernetPacket=(EthernetPacket)packet.datalink;//取出以太网帧部分数据
            att.put("Source MAC", ethernetPacket.getSourceAddress());//源MAC地址
            att.put("Destination MAC", ethernetPacket.getDestinationAddress());//目的MAC地址
            if(ethernetPacket.frametype == 2054){//类型为ARP，打印
                att.put("Type", "ARP(2054)");
            }
            if(ethernetPacket.frametype == 2048){//类型为IP，打印
                att.put("Type", "IPv4(2048)");
            }
        }
        return att;
    }

    public static LinkedHashMap<String,String> ARPanalyze(){//ARP分析
        att = new LinkedHashMap<String,String>();
        if(packet instanceof ARPPacket){
            ARPPacket arppacket = (ARPPacket) packet;
            EthernetPacket e = (EthernetPacket) arppacket.datalink;//以太网帧部分数据
            att.put("Protocol", ("ARP"));//协议
            att.put("Destination",e.getDestinationAddress());//目的MAC地址
            att.put("Source",e.getSourceAddress());//源MAC地址
            att.put("Hardware type",String.valueOf(arppacket.hardtype));//硬件类型
            att.put("Protocol type",String.valueOf(arppacket.prototype));//协议类型
            att.put("Hardware size",String.valueOf(arppacket.hlen));//硬件地址长度
            att.put("Protocol size",String.valueOf(arppacket.plen));//协议地址长度
            if(arppacket.operation == 1){//操作类型，请求
                att.put("Opcode","request(1)");
            }
            if(arppacket.operation == 2){//操作类型，应答
                att.put("Opcode","reply(2)");
            }
            att.put("Sender MAC address", String.valueOf(arppacket.getSenderHardwareAddress()));//发送方MAC地址
            att.put("Sender IP address", String.valueOf(arppacket.getSenderProtocolAddress()));//发送方IP地址
            att.put("Target MAC address", String.valueOf(arppacket.getTargetHardwareAddress()));//接收方MAC地址
            att.put("Target IP address", String.valueOf(arppacket.getTargetProtocolAddress()));//接收方IP地址
            att.put("","ARP");
        }
        return att;
    }
    public static LinkedHashMap<String,String> IPanalyze(){//IP首部分析
        att = new LinkedHashMap<String,String>();
        if(packet instanceof IPPacket && ((IPPacket)packet).version == 4){//IPv4
            IPPacket ippacket = (IPPacket) packet;
            att.put("Version", String.valueOf(ippacket.version));//版本
            att.put("TOS",String.valueOf(ippacket.rsv_tos));//服务类型
            att.put("Total Length", String.valueOf(ippacket.length));//总长度
            att.put("Identification", String.valueOf(ippacket.ident));//标识
            att.put("Don't fragment", String.valueOf(ippacket.dont_frag));//DF标志位
            att.put("More fragments", String.valueOf(ippacket.more_frag));//MF标志位
            att.put("Fragment offset", String.valueOf(ippacket.offset));//数据片偏移
            att.put("Time to live", String.valueOf(ippacket.hop_limit));//生存时间
            if(ippacket.protocol == 6){//报文数据类型
                att.put("Protocol", ("TCP"));
            }
            else if(ippacket.protocol == 1){
                att.put("Protocol", ("ICMP"));
            }
            else if(ippacket.protocol == 17){
                att.put("Protocol", ("UDP"));
            }
            else{
                att.put("Protocol", String.valueOf(ippacket.protocol));
            }
            att.put("Source", ippacket.src_ip.toString().substring(1));//源IP地址
            att.put("Destination", ippacket.dst_ip.toString().substring(1));//目的IP地址
            att.put("","IP");
        }
        return att;
    }
    public static LinkedHashMap<String,String> ICMPanalyze(){//ICMP报文分析
        att = new LinkedHashMap<String,String>();
        ICMPPacket icmppacket = (ICMPPacket) packet;
        att.put("Protocol", ("ICMP"));//协议
        att.put("Source IP", icmppacket.src_ip.toString().substring(1));//源IP地址
        att.put("Destination IP", icmppacket.dst_ip.toString().substring(1));//目的IP地址
        att.put("Type", String.valueOf(icmppacket.type));//报文类型
        att.put("Code", String.valueOf(icmppacket.code));//ICMP报文代码
        att.put("Checksum", String.valueOf(icmppacket.checksum));//检验和
        return att;
    }
    public static LinkedHashMap<String,String> TCPanalyze(){//TCP报文分析
        att = new LinkedHashMap<String,String>();
        TCPPacket tcppacket = (TCPPacket) packet;
        att.put("Protocol", ("TCP"));//协议
        att.put("Source Port", String.valueOf(tcppacket.src_port));//源端口
        att.put("Destination Port", String.valueOf(tcppacket.dst_port));//目的端口
        att.put("Sequence Number", String.valueOf(tcppacket.sequence));//序号
        att.put("Acknowledge Number", String.valueOf(tcppacket.ack_num));//确认号
        att.put("Head length",String.valueOf(4*(tcppacket.header[46] & 0xff)>>4));//数据偏移，以4字节为单位
        att.put("Urgent Flag", String.valueOf(tcppacket.urg));//URG标志位
        att.put("Ack Flag", String.valueOf(tcppacket.ack));//ACK标志位
        att.put("Push Flag", String.valueOf(tcppacket.psh));//PSH标志位
        att.put("Reset Flag", String.valueOf(tcppacket.rst));//RST标志位
        att.put("Syn Flag", String.valueOf(tcppacket.syn));//SYN标志位
        att.put("Fin Flag", String.valueOf(tcppacket.fin));//FIN标志位
        att.put("Window Size", String.valueOf(tcppacket.window));//窗口
        int a=(tcppacket.header[50] & 0xff)<<8;//位运算后左移一个字节长度
        int b=(tcppacket.header[51] & 0xff);
        int result = a|b;//或运算把相当于把a和b加起来
        att.put("Check Sum", String.valueOf(result));//转换成十进制输出 检验和
        att.put("Urgent Pointer", String.valueOf(tcppacket.urgent_pointer));//紧急指针
        att.put("Source IP", tcppacket.src_ip.toString().substring(1));//源IP地址
        att.put("Destination IP", tcppacket.dst_ip.toString().substring(1));//目的IP地址
        /*把数据部分字节流转换为十六进制输出*/
        int ilen1 = tcppacket.data.length;
        StringBuffer sb1 = new StringBuffer(ilen1 * 2);
        for(int i = 0; i < ilen1; i++){
            int intTmp = tcppacket.data[i];
            while (intTmp < 0){
                intTmp = intTmp + 256;//补码换原码
            }
            if(intTmp < 16){
                sb1.append("0");
            }
            sb1.append(Integer.toString(intTmp, 16));
            if(Math.floorMod( (i+1),1) == 0){
                sb1.append(" ");
            }
        }
        String ss1 = sb1.toString();
        att.put("Data", ss1);//TCP数据
        return att;
    }
    public static LinkedHashMap<String,String> UDPanalyze(){//UDP报文
        att = new LinkedHashMap<String,String>();
        UDPPacket udppacket = (UDPPacket) packet;
        att.put("Protocol", ("UDP"));//协议
        att.put("Source Port", String.valueOf(udppacket.src_port));//源端口
        att.put("Destination Port", String.valueOf(udppacket.dst_port));//目的端口
        att.put("Length", String.valueOf(udppacket.length));//长度
        /*取字段偏移值求检验和字段*/
        int a=(udppacket.header[40] & 0xff)<<8;
        int b=(udppacket.header[41] & 0xff);
        int result = a|b;
        att.put("Check Sum", String.valueOf(result));
        /*把数据部分字节流转换为十六进制输出*/
        int ilen = udppacket.header.length;
        StringBuffer sb = new StringBuffer(ilen * 2);
        for(int i = 0; i < ilen; i++){
            int intTmp = udppacket.header[i];
            while (intTmp < 0){
                intTmp = intTmp + 256;
            }
            if(intTmp < 16){
                sb.append("0");
            }
            sb.append(Integer.toString(intTmp, 16));
            if(Math.floorMod( (i+1),1) == 0){
                sb.append(" ");
            }
        }
        String ss = sb.toString();
        att.put("Data", ss);//UDP数据
        return att;
    }

    public static int byte2int(byte[] data,int low_index){
        int a = (data[low_index] & 0xff)<<24;
        int b = (data[low_index+1] & 0xff)<<16;
        int c = (data[low_index+2] & 0xff)<<8;
        int d = (data[low_index+3] & 0xff);
        int result = a|b|c|d;
        return result;
    }
}
