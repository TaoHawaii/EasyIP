/* Install libpcap-dev */
/* To compile: g++ Easy_IP_Address.c -o Easy_IP_Address -lpcap                       */
/* Add a bogus HOST alias to your /etc/hosts file I.E. "1.1.1.1 HOST" */
/* Run as root I.E. ./Easy_IP_Address eth0                                                          */

//#include <pcap.h>
//#include <stdlib.h>
//#include <string.h>
#include <unistd.h>
#include <stdlib.h>
//#include <sstream>
#include <netinet/in.h>

#include <stdio.h>
#include <sys/types.h>
//#include <sys/socket.h>
//#include <sys/ioctl.h>
//#include <net/if.h>
#include <arpa/inet.h>
#include "nic.c"
#include "capture.c"

/* ARP Header, (assuming Ethernet+IPv4)         */
#define ARP_REQUEST 1                           /* ARP Request             */
#define ARP_REPLY 2                             /* ARP Reply               */
typedef struct arphdr
{
	u_int16_t htype;                              /* Hardware Type           */
	u_int16_t ptype;                              /* Protocol Type           */
	u_char hlen;                                  /* Hardware Address Length */
	u_char plen;                                  /* Protocol Address Length */
	u_int16_t oper;                               /* Operation Code          */
	u_char sha[6];                                /* Sender hardware address */
	u_char spa[4];                                /* Sender IP address       */
	u_char tha[6];                                /* destination hardware address */
	u_char tpa[4];                                /* destination IP address       */
}arphdr_t;


/*
 * Every time an arp is received (a lot)
 *  Look to see that it is not us (we only connect directly to a single computer)
 *  If the externally generated ARP has a NEW IP address, reconfigure our NIC to use the next higher.
 *  If the IP is already as high as it can go, we use the next lower.
 * Everything is hard coded to class C networks... (This is unnecessary because there are only two of us...)
 */

int main(int argc, char *argv[])
{
	if (argc != 2)
	{
	    printf("USAGE: ./Easy_IP_Address <interface>\n");
	    exit(1);
	}


	char soctet1[4], soctet2[4], soctet3[4], soctet4[4];
	char toctet1[4], toctet2[4], toctet3[4], toctet4[4];
	int myhost_octet;                             // The numeric value of my host address
	int i=0;                                      // An iterator
	arphdr_t *arpheader = NULL;                   /* Pointer to the ARP header              */

	time_t tick = time (NULL);
	int threshold = 10;
	bool timer_enabled=false;


  Capture capture;
  Nic nic(argv[1],"1.1.1.1");

  nic.queryLocalNicDeviceConfig();
	printf("My IP: %s\n", nic.getCurrentIP());

// Print my NIC's MAC address
	printf("My MAC: %s\n", nic.getMacAddress());

  try 
  {
    if (capture.start(nic.getName()) == -1 || capture.lookupDeviceConfig(nic.getName) == -1)
    {
      throw(capture.getErrBuff());
    }
  }
  catch (char errbuf)
  {
    fprintf(stderr, "ERROR: %s\n", errbuf);
    exit(1);
  }

  try
  {
    if (capture.compileArpFilter() == -1 || capture.loadCompiledFilter() == -1)
    {
      throw capture.getPcapInstanceDescriptor();
    }
  }
  catch (pcap_t* descr)
  {
	  fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
	  exit(1);
  }

	while(1)                                      //Forever... As long as we have an IP address... Bad move could just be down?
	{
    capture.waitForeverForCapturedPacket();

//Get my current IP again in case it changed, as it does often when testing this code.
	    nic.queryConfig();

	    arpheader = (struct arphdr *)(capture.getCapturedPacket+14); /* Point to the ARP header */

	    printf("\n\nReceived Packet Size: %d bytes\n", capture.getPcapPacketHeader.len);
	    printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
	    printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
	    printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

/* If is Ethernet and IPv4, get package goodies */
	    if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
	    {
	        printf("Sender MAC: ");

	        char mac_part[3] = "";
          capture.m_potentialNetHostSenderMac.clear();
	        for(i=0; i<6;i++)
	        {
	            printf("%02X ", arpheader->sha[i]);
	            sprintf(mac_part,"%02X",arpheader->sha[i]);
              capture.m_potentialNetHostSenderMac<<mac_part;
	        }

	        printf("\nOriginator IP: ");

	        for(i=0; i<4;i++)
          {
	            printf("%d ", arpheader->spa[i]);
          }

	        sprintf(soctet1,"%d",arpheader->spa[0]);
	        sprintf(soctet2,"%d",arpheader->spa[1]);
	        sprintf(soctet3,"%d",arpheader->spa[2]);
	        sprintf(soctet4,"%d",arpheader->spa[3]);

          capture.m_netPacketOriginatorIp.clear();
          capture.m_netPacketOriginatorIp<<soctet1<<"."<<soctet2<<"."<<soctet3<<"."<<soctet4

// Potential host octet, what it will be IF a change is made...
//TODO:Fix this so it actually finds an open IP instead of just adding one...
//(in case of connection to network switch)
	        if(arpheader->spa[3] < 254)
	            myhost_octet = arpheader->spa[3]+1;
	        else
	            myhost_octet = arpheader->spa[3]-1;

	        printf("\nDestination MAC: ");

	        for(i=0; i<6;i++)
          {
	            printf("%02X ", arpheader->tha[i]);
          }

	        printf("\nDestination IP: ");

	        sprintf(toctet1,"%d",arpheader->tpa[0]);
	        sprintf(toctet2,"%d",arpheader->tpa[1]);
	        sprintf(toctet3,"%d",arpheader->tpa[2]);
	        sprintf(toctet4,"%d",arpheader->tpa[3]);

	        capture.m_netPacketDestinationIp.clear();
          capture.m_netPacketDestinationIp<<toctet1<<"."<<toctet2<<"."<<toctet3<<"."<<toctet4

	        printf("%s\n", destination_ip.str().c_str());

//This occurs as long as the sender doesn't change.
//If we don't get any new arp challenges, this won't change.
	        if(capture.m_potentialNetHostSenderIp.str() != capture.m_connectedNetHostSenderIp.str())
	        {
	            tick = time(NULL);
	            printf("tick: %ld\n", tick);
	        }

//If sender MAC NOT myself, AND sender IP HAS changed (since the last challenge was made)...
//                                                              ,this could be a toggle BACK to my current_sender_ip after an unsuccessful challenge
	        if(strcmp(capture.m_potentialNetHostSenderMac.str().c_str(),nic.getMacAddress()) != 0)
	        {
	            //system("arping -c 1 -q -b -I nic.getName() HOST");
	            printf("\nLast challenging connection: %s", capture.m_netPacketOriginatorIp.str().c_str());
	            printf("\nMy current connection is with: %s\n\n", capture.m_connectedNetHostSenderIp.str().c_str());
	            printf("sender_ip diffs originator_ip:sender_mac != nic.getMacAddress()\n");
// If different, allow it to toggle sender_ip
// Let the challenger be introduced!
              capture.m_potentialNetHostSenderIp.clear();
              capture.m_potentialNetHostSenderIp<<soctet1<<"."<<soctet2<<"."<<soctet3<<"."<<soctet4

	            if(capture.m_potentialNetHostSenderIp.str().c_str() != capture.m_connectedNetHostSenderIp.str())
	            {   // Toggle back to my current_sender_ip, reset everything and go on like nothing ever happened.
	                printf("Yay, we are ourselves again!\n");
	            }
	            else
	            {
// This was meant to stimulate the current sender into producing traffic...  It doesn't work...
//  And worse, we see this traffic and we get confused...  Uncomment when you are ready to fix this.
//   The benefits of this code is that this would work on a switched network without "flapping".
//                      printf("arping HOST @ %s\n", current_sender_ip);
//                      system("arping -c 1 -q -b -I nic.getName() HOST");
//                      printf("Time: %ld\nTick: %ld\n", time(NULL), tick);

// Time tick will be used when the above is fixed.  For now, we just always change when we see an ARP change.
//                    if(time(NULL)-tick > threshold)
//                    {
	                    printf("Challenge processed @: %ld\n", tick);
                      capture.m_potentialNetHostSenderIp.clear();
                      capture.m_potentialNetHostSenderIp<<soctet1<<"."<<soctet2<<"."<<soctet3<<"."<<soctet4

                      capture.m_connectedNetHostSenderIp.clear();
                      capture.m_connectedNetHostSenderIp<<soctet1<<"."<<soctet2<<"."<<soctet3<<"."<<soctet4

//This will update your static IP configuration (check the format and location of the network configuration file below)
//                        std::stringstream ifcfg_stream;
//                        ifcfg_stream << "sed -i 's|IPADDR=.*$|IPADDR=" << soctet1 << "." << soctet2 << "." << soctet3 << "." << myhost_octet << "|' " << "/etc/sysconfig/network-scripts/ifcfg-" << nic.getName();
//                        const char* sed_cmd = ifcfg_stream.str().c_str();
//                        printf("\n\nsed_cmd: %s\n", sed_cmd);
//                        system(sed_cmd);

//Uncomment this is you want the network service restarted every time the mac changes...
//                        std::stringstream nic_stream;
//                        nic_stream << "ifdown " << nic.getName() << " && ifup " << nic.getName();
//                        const char* nic_toggle = nic_stream.str().c_str();
//                        printf("\n\nnic_toggle: %s\n", nic_toggle);
//                        system(nic_toggle);

// You might have to update all of these if your system no longer uses or supports the ifconfig command (boo).
// Sigh, change makes me realize I'm getting old and grouchy...
// Also, this is another place where class C networks are hard coded... =)
	                    std::stringstream ifcfgCommand;
	                    ifcfgCommand<<soctet1<<"."<<soctet2<<"."<<soctet3<<"."<<myhost_octet;
                      nic.setLocalNicDeviceIp(ifcfgCommand.str().c_str());
	                    printf("\n\nifcfg_toggle: %s\n", ifcfgCommand);

// You will always be able to talk to your directly connected computer by using the "HOST" alias.
//  Without having to know or keep track of the IP address.
	                    char hosts_file[] = "/etc/hosts";
	                    std::stringstream hosts_stream;
	                    hosts_stream << "sed -i 's|.*HOST|" << capture.m_netPacketOriginatorIp.str().c_str() << " HOST|' " << hosts_file;
	                    const char* sed_hosts = hosts_stream.str().c_str();
	                    printf("\n\nsed_cmd: %s\n", sed_hosts);
	                    system(sed_hosts);

	                    capture.freeCapturedPacket();//Set for next while loop
// This is just the end of the commented if(tick) {
//                    }
	            }
	        }
	        capture.freeCapturedPacket();//Set for next while loop
	    }
	}
	return 0;
}


