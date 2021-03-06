# Network-Capture-Package
简单网络抓包工具（支持tcp、udp、icmp、arp）使用jpcap接口

设计一个网络协议解析器，能够实现一个抓包工具的基本功能：

1.有一定的可视化界面。可对不同协议的包进行分析，此次实验我们重点分析 UDP、TCP、 ICMP和ARP四种协议的数据包。

2.可选择网络设备对网络数据包进行抓包，将抓包信息打印在表格中显示出来。

3.抓包线程可开始可停止，要灵活执行。

4.设置一定的过滤规则，过滤出我们需要的数据包，过滤规则要尽可能详细且满足基本要求。

5.双击表格项可查看数据包的具体信息以及结构，首部各字段、数据部分都可以看到。

6.有保存的功能可以选择保存抓到的全部数据包、过滤规则下显示的数据包还是单个指定的数据包，可选择将数据包的具体信息保存到本地的任意位置。

## 使用
直接使用MySniffer.exe即可，使用的是exe4j将jar包打包为exe文件

## 运行

![image1](https://github.com/a123wyn/Network-Capture-Package/blob/master/images/%E5%9B%BE%E7%89%871.png)

![image2](https://github.com/a123wyn/Network-Capture-Package/blob/master/images/%E5%9B%BE%E7%89%872.png)

![image3](https://github.com/a123wyn/Network-Capture-Package/blob/master/images/%E5%9B%BE%E7%89%873.png)
