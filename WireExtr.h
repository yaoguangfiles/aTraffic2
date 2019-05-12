
#ifndef WIREEXTR_H_
#define WIREEXTR_H_

#include <string>
#include <vector>
#include <map>
#include <algorithm>
#include <iostream>
#include <pcap.h>
#include <stdint.h>
#include <cmath>
#include <iostream>     // std::cout
#include <sstream>      // std::stringstream, std::stringbuf
#include <stdio.h>
#include <string.h>
//#include <cstdint.h>
#include "CRC.hh"

#define MAX_NUM_LAPS 3
#define MAX_NUM_MACH 20 // the max number of machines from an Access Point used
//#define MAX_NUM_LAPS 64
#define POS_SUBTYPE 18 // the position of subtype field in 802.11b frame
#define POS_SRC_MAC 28 // the source mac address starts at this position
#define LEN_MAC_ADDR 18 // the length of mac address including ':'

using namespace std;

struct Pkt_Line
{
	long int pkt_no; // the packet number I gave
	long int timestamp; // the timestamp of packet starting from 0

	char src_macAddr[LEN_MAC_ADDR]; // the source mac address including ':'
	char dest_macAddr[LEN_MAC_ADDR]; // the distination mac address including ':'

	int len_pkt; // the packet length
	uint8_t lapSub_id; // the lap sub id

	Pkt_Line(long int pkt_no, long int timestamp
			, char src_macAddr[], char dest_macAddr[], int len_pkt, uint8_t lapSub_id)
	{
		this->pkt_no = pkt_no;
		this->timestamp = timestamp;

//		this->src_macAddr = src_macAddr;
//		this->dest_macAddr = dest_macAddr;

		strncpy(this->src_macAddr, src_macAddr, LEN_MAC_ADDR);
		strncpy(this->dest_macAddr, dest_macAddr, LEN_MAC_ADDR);

		this->len_pkt = len_pkt;
		this->lapSub_id = lapSub_id;
	}
};

class WireExtr
{
public:

	bool isDebug = false;
	const string file = "/home/rootroot/files/traffic/traffic_1m.pcap";
	const int Num_Folds = 4; // the number of folds to divide traffic trace into

	long int time_start = 0;
//	long int time_last = 1451151774; // the timestamp the last packet was received

	// the number of packets a machine sent
	// mach[mac_addr] = no. of packets sent
	map<vector<unsigned char>,long> mach;

	// map the machines in the traffic trace with the laps
	// laps_map[lapRec_id] = {mac_addr1, mac_addr2, ...};
	map<uint8_t,vector<vector<unsigned char>>> laps_map;

	vector<unsigned char> mac_broadcast {0xff,0xff,0xff,0xff,0xff,0xff};
	vector<unsigned char> mac_src_chk {0x8c,0x0f,0x6f,0xad,0x98,0x28};
	char mac_ff[18] = "ff:ff:ff:ff:ff:ff";

	std::vector<Pkt_Line> vec_pkt; // the vector contains all the packets from traffic trace

//	long int tmStamp_last = 0; // the larget timestamp in the traffic trace

	WireExtr();
	virtual ~WireExtr();
	void convToTxt(const std::string& file_wireshark);
	void printAddr(char* title, std::vector<unsigned char> addr);
	void printAddr(std::vector<unsigned char> addr);
	string hexToStr(int num);
	void fill_macAddr(char macAddr[], int len_macAddr, std::vector<unsigned char> destAddr_mac);
	void print_pktType(u_int packetCount, const u_char *data);
	void print_machPktRecv(vector<std::pair<vector<unsigned char>, int>> mach_sort);
	void print_machLapMappint(map<uint8_t,vector<vector<unsigned char>>> laps_map);
};

#endif /* WIREEXTR_H_ */
