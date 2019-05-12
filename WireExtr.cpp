
// compile & link:
//     make clean
//     make

// run:
//     ./main > /home/rootroot/files/traffic/traffic_com_4fold.txt

#include "WireExtr.h"

// **** WireExtr() ****
WireExtr::WireExtr()
{}

// **** convToTxt() ****
void WireExtr::convToTxt(const std::string& file_wireshark)
{
    char errbuff[PCAP_ERRBUF_SIZE];

    pcap_t * pcap = pcap_open_offline(file_wireshark.c_str(), errbuff);

    if (pcap == NULL)
	{
		printf("(Error): Failed to call pcap_open_offline().\n\n");
		return;
	}

    if(WireExtr::isDebug)
		printf("(D): In WireExtractor::getAllWireDataPackets(): WireExtractor::file_pcap=%s\n"
				, file_wireshark.c_str()); // Show the size in bytes of the packet

    struct pcap_pkthdr *header;
    const u_char *data;
    u_int packetCount = 0;
    int num_read = 3000;

    int lower = 0;
    int upper = 5000;
    int num_dataPkt = 0;

    int MAC_DATA_DIFF = 22; // = DATA_START - MAC_ADDR_START
    int MAC_ADDR_START = 28;

    int DATA_START = MAC_ADDR_START + MAC_DATA_DIFF; // data field will start after number: MAC_DATA_DIFF


    if(WireExtr::isDebug)
		printf("(D): WireExtractor.cpp: MAC_ADDR_START=%d,DATA_START=%d\n",MAC_ADDR_START,DATA_START);

    int returnValue;

    while (returnValue = pcap_next_ex(pcap, &header, &data) >= 0)
    {
        // Show the packet number
        ++packetCount;

//        if(WireExtr::isDebug)
        {
//        	if (packetCount >= lower && packetCount <= upper)
			{
        		if(WireExtr::isDebug)
        			print_pktType(packetCount, data);

				long int sec = header->ts.tv_sec;
				long int micro_sec = header->ts.tv_usec;

				long int tmStamp = sec * 1000000 + micro_sec;

				if(time_start == 0 )
					time_start = tmStamp;
				tmStamp = tmStamp - time_start;

				const unsigned char *start = data + MAC_ADDR_START;
				std::vector<unsigned char> srcAddr_mac(start, start + 6); // = new char[6+1];

				std::vector<unsigned char> destAddr_mac(start-6, start); // = new char[6+1];

				long int pkt_len = header->len;

				const int Len_MacAddr = 18;

				// ---- Begin: copy dest mac addr from vector to char[] ----
				char dest_mac[Len_MacAddr];
				char src_mac[Len_MacAddr];

				fill_macAddr(dest_mac, Len_MacAddr, destAddr_mac);
				if( strncmp(dest_mac, mac_ff, 17) == 0 )
					continue;

				fill_macAddr(src_mac, Len_MacAddr, srcAddr_mac);
				if( strncmp(src_mac, mac_ff, 17) == 0 )
					continue;

				// Use CRC hashing function to map machines to laps
				std::string input(dest_mac);
				uint32_t crc = CRC::Calculate(dest_mac, sizeof(dest_mac), CRC::CRC_32());
				uint8_t lapSub_id = crc % 3;

				vec_pkt.push_back(Pkt_Line(packetCount,tmStamp,src_mac,dest_mac,pkt_len,lapSub_id));

				++mach[destAddr_mac];
			}
        }
	}

    long int tmStamp_last = -1; // the larget timestamp in the traffic trace

    if(vec_pkt.size() > 0)
    	tmStamp_last = vec_pkt.back().timestamp;

    // the average duration for segments of traffic trace
    int avg_dur = ceil( (double) tmStamp_last / (double) Num_Folds);

//    printf("(D): avg_dur: %d\n", avg_dur);

    // divide the packets in the traffic trace into [Num_Folds] number of
    // segments based on the packet's timestamp
    for (std::vector<Pkt_Line>::iterator it = vec_pkt.begin(); it != vec_pkt.end(); it++)
	{
    	while(it->timestamp >= avg_dur)
    		it->timestamp -= avg_dur;
	}

    // Using lambda expressions in C++11 to sort the vector of objects
	sort(vec_pkt.begin(), vec_pkt.end(), [](const Pkt_Line& lhs, const Pkt_Line& rhs)
	{
		return lhs.timestamp < rhs.timestamp;
	});

//    printf("vec_pkt:\n");

    for (std::vector<Pkt_Line>::iterator it = vec_pkt.begin(); it != vec_pkt.end(); it++)
    {
    	printf("%ld,%ld,%s,%s,%d,%d\n", it->pkt_no, it->timestamp, it->src_macAddr
    			, it->dest_macAddr, it->len_pkt, it->lapSub_id);

//    	// for matlab traffic_chart.txt
//    	printf("%ld,%ld,%d,%d\n", it->pkt_no, it->timestamp, it->len_pkt, it->lapSub_id);
    }

    // will sort the machines based on number of packets they received
    vector<std::pair<vector<unsigned char>, int>> mach_sort;

    for (map<vector<unsigned char>,long>::iterator itr = mach.begin(); itr != mach.end(); ++itr)
    	mach_sort.push_back(*itr);

    sort(mach_sort.begin(), mach_sort.end(), [=](pair<vector<unsigned char>, int>& a, pair<vector<unsigned char>, int>& b)
    {
        return a.second > b.second;
    });

    if(WireExtr::isDebug)
    	print_machPktRecv(mach_sort);

    int num_mach = mach_sort.size();

    if(num_mach > MAX_NUM_MACH)
    	num_mach = MAX_NUM_MACH;

    int fold = num_mach / MAX_NUM_LAPS;

    for(int i_lap = 0; i_lap < MAX_NUM_LAPS; ++i_lap)
    {
    	vector<vector<unsigned char>> mchs;

    	for(int i_mch = i_lap * fold; i_mch < (i_lap+1) * fold; ++i_mch)
    	{
    		bool is_broadcast = std::equal(mach_sort[i_mch].first.begin(), mach_sort[i_mch].first.begin() + 6,mac_broadcast.begin());

    		if(!is_broadcast)
    			mchs.push_back(mach_sort[i_mch].first);
    	}

    	laps_map[i_lap] = mchs;
    }

    if(WireExtr::isDebug)
    	print_machLapMappint(laps_map);

    if(WireExtr::isDebug)
		printf("(D): In WireExtractor::getAllWireDataPackets(): done the method.\n");
}

// **** printAddr() ****
void WireExtr::printAddr(char* title, std::vector<unsigned char> addr)
{
	printf("%s: ",title);

	for(unsigned i = 0; i < addr.size(); ++i)
	{
		if(i == 0)
			printf("%2x", addr[i]);
		else
			printf(":%2x", addr[i]);
	}

	printf("\n");
}

// **** printAddr() ****
void WireExtr::printAddr(std::vector<unsigned char> addr)
{
	string prefix = "";

	for(unsigned i = 0; i < addr.size(); ++i)
	{
		// if addr[i] is only a place in term of hex decimal
		if(addr[i] < 16)
			prefix = "0";
		else
			prefix = "";

		if(i == 0)
			printf("%s%x", prefix.c_str(), addr[i]);
		else
			printf(":%s%x", prefix.c_str(), addr[i]);
	}
}

// **** hexToStr() ****
string WireExtr::hexToStr(int num)
{
	string ret;

	std::stringstream ss;
	ss << std::hex << num;
	ret = ss.str();

	if(ret.length() == 1)
		ret = "0" + ret;

	return ret;
}

// **** fill_macAddr() ****
void WireExtr::fill_macAddr(char macAddr[], int len_macAddr, std::vector<unsigned char> destAddr_mac)
{
	for(int i = 0; i < destAddr_mac.size(); ++i)
	{
		string str_hex = hexToStr(destAddr_mac[i]);

		int start_pos = i * 3;
		strncpy(&macAddr[start_pos], str_hex.substr(0,1).c_str(), 1);
		strncpy(&macAddr[start_pos+1], str_hex.substr(1,1).c_str(), 1);
		macAddr[start_pos+2] = ':';
	}

	macAddr[len_macAddr-1] = '\0';
}

// **** print_pktType() ****
void WireExtr::print_pktType(u_int packetCount, const u_char *data)
{
	printf("\n*) packetCount # %i\n",packetCount);

	for (u_int i = 0; i < 100; i++)
	{
		if ((i % 16) == 0)
			printf("\n");

		if ((i % 8) == 0)
			printf("  ", data[i]);

		printf("%.2x ", data[i]);
	}

	printf("\n\n");

	uint8_t subtype_byte = data[POS_SUBTYPE];

	printf("subtype_byte[%d]: %.2x\n", POS_SUBTYPE, subtype_byte);

	uint8_t subtype_nibble = subtype_byte >> 4;
	printf("subtype_nibble[%d]: %.2x\n", POS_SUBTYPE, subtype_nibble);

	//++ also need to check ToDS and FromDS bits,
	// see http://www.fedu.uec.ac.jp/~thavisak/Tech-Link/IEEE802.11b/IEEE80211b.htm
	if(subtype_nibble == 8)
		printf("Beacon: yes(%.2x)\n", subtype_nibble);
	else
		printf("Beacon: no(%.2x)\n", subtype_nibble);

	// if the subtype management bits, e.g. Type (b3 b2) in
	// (page: http://www.fedu.uec.ac.jp/~thavisak/Tech-Link/IEEE802.11b/IEEE80211b.htm)
	// is "00", and subtype_nibble, e.g. Subtype (b7 b6 b5 b4) is "1000", it is a
	// beacon frame.
	uint8_t subtype_Management = subtype_byte & 0b00001100;
	printf("subtype_Management[%d]: %.2x\n", POS_SUBTYPE, subtype_Management);

	if(subtype_Management == 0)
		printf("Management bits(b3,b2)=00: yes(%.2x)\n", subtype_Management);

	printf("\n\n");
}

// **** print_machPktRecv() ****
// print the number of pakets the machine received
void WireExtr::print_machPktRecv(vector<std::pair<vector<unsigned char>, int>> mach_sort)
{
	cout << "Before: key-element:\n";

	map<vector<unsigned char>,long>::iterator itr;

	for (itr = mach.begin(); itr != mach.end(); ++itr)
	{
		printAddr("src_mac", itr->first);
		cout<< '\t' << itr->second << '\n';
	}
	cout << endl;


	cout << "After sort: key-element:\n";
	vector<std::pair<vector<unsigned char>, int>>::iterator itr2;
	for (itr2 = mach_sort.begin(); itr2 != mach_sort.end(); ++itr2)
	{
		printAddr("src_mac", itr2->first);
		cout<< '\t' << itr2->second << '\n';
	}
	cout << endl;
}

// **** print_machLapMappint() ****
void WireExtr::print_machLapMappint(map<uint8_t,vector<vector<unsigned char>>> laps_map)
{
	for (map<uint8_t,vector<vector<unsigned char>>>::iterator itr = laps_map.begin(); itr != laps_map.end(); ++itr)
	{
		printf("\n*) For lap: %d:\n",itr->first);

		vector<vector<unsigned char>> machs_mac = itr->second;

		for (vector<vector<unsigned char>>::iterator itr2 = machs_mac.begin(); itr2 != machs_mac.end(); ++itr2)
		{
			printAddr(*itr2);
			printf("\n");
		}

	}
}

// **** ~WireExtr() ****
WireExtr::~WireExtr()
{}

