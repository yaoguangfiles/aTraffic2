
// run: ./main > /home/rootroot/files/traffic/traffic_test_10k.txt

#include <iostream>
#include "WireExtr.h"

using namespace std;

void gener_testTraffic(int num_pkts, int interv_pkts);

int main(int argc, char** argv)
{
	//---- Begin: Generate testing traffic trace for testing the program ----

	int NUM_PKTS = 300000 * 2; // number of packets generated
//	int NUM_PKTS = 150000 * 2; // number of packets generated
	int INTERV_PKTS = 56; // interval between two consecutive packets

	gener_testTraffic(NUM_PKTS, INTERV_PKTS);

	//---- End: Generate testing traffic trace for testing the program ----

	//---- Begin: Convert IP packets in traffic trace to text file ----
//	WireExtr extr = WireExtr();
//	extr.convToTxt(extr.file);
	//---- End: Convert IP packets in traffic trace to text file ----

	return 0;
}

// generate testing traffic trace for testing the WhiteStar program
void gener_testTraffic(int num_pkts, int interv_pkts)
{
//	int num_pkts = 100; // number of packets generated
//	int interv_pkts = 50; // interval between two consecutive packets

	long int timeStampe = 0;
	long int timeStampe_tx0 = 0; // timestamp for packets to gap tx0
	long int timeStampe_tx1 = 0; // timestamp for packets to gap tx1

	/*
	// d8:31:34:25:91:92,8c:0f:6f:ad:98:28
	std::vector<unsigned char> mac_lap0 {0x8c,0x0f,0x6f,0xad,0x98,0x28}; // map to lap 0
	// 94:6a:b0:0d:0f:fb,54:3d:37:2b:2d:a8
	std::vector<unsigned char> mac_lap1 {0x54,0x3d,0x37,0x2b,0x2d,0xa8}; // map to lap 1
	// 54:3d:37:2c:9e:e8,b0:fc:0d:35:57:f6
	std::vector<unsigned char> mac_lap2 {0xb0,0xfc,0x0d,0x35,0x57,0xf6}; // map to lap 2

	std::vector<std::vector<unsigned char>> laps;
	laps.push_back(mac_lap0);
	laps.push_back(mac_lap1);
	laps.push_back(mac_lap2);
	*/

	const int NUM_LAP_USED = 3;
	string mac_src[NUM_LAP_USED];
	mac_src[0] = "d8:31:34:25:91:92";
	mac_src[1] = "94:6a:b0:0d:0f:fb";
	mac_src[2] = "54:3d:37:2c:9e:e8";

	string mac_dest[NUM_LAP_USED];
	mac_dest[0] = "8c:0f:6f:ad:98:28";
	mac_dest[1] = "54:3d:37:2b:2d:a8";
	mac_dest[2] = "b0:fc:0d:35:57:f6";

	int len_pkt = 140; // the size IP packets
	int lapSub_id = 0; // the lap sub id

	int const num_type_pkt = 4;

	for(long int i = 0; i < num_pkts; ++i)
	{
//		lapSub_id = i % NUM_LAP_USED;
		lapSub_id = i % num_type_pkt;
//		timeStampe += interv_pkts;

		if(lapSub_id == 3)
			lapSub_id = 1;

		if(lapSub_id == 1)
		{
			timeStampe_tx1 += interv_pkts;
			timeStampe = timeStampe_tx1;
		}else
		{
			timeStampe_tx0 += interv_pkts;
			timeStampe = timeStampe_tx0;
		}

		printf("%ld,%ld,%s,%s,%d,%d\n", i, timeStampe, mac_src[lapSub_id].c_str()
				, mac_dest[lapSub_id].c_str(), len_pkt, lapSub_id);
	}
}

