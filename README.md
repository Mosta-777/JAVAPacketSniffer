# JAVAPacketSniffer


The Java packet sniffer is a very simple packet sniffer developed ( Obviously :D ) in java ,
the user has the ability to choose the network interface to sniff on , start or stop sniffing ,
visiualize basic and detailed information about packet , save packets in pcap formats and filter packets ,
The filter is built from a human friendly textual expression using libpcap filter syntax.
The expression, presented as a string, is filter compiled to a PcapBpfProgram which holds the binary representationof the filter expression .
The program uses JNetPcap java library to do it's various functionalities from scanning available network interfaces
to sniffing and filtering packets ,
