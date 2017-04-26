/* Install libpcap-dev */
/* To compile: g++ Easy_IP_Address.c -o Easy_IP_Address -lpcap                       */
/* Add a bogus HOST alias to your /etc/hosts file I.E. "1.1.1.1 HOST" */
/* Run as root I.E. ./Easy_IP_Address eth0                                                          */

#include <pcap.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sstream>
#include <netinet/in.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>

/* ARP Header, (assuming Ethernet+IPv4)            */
#define ARP_REQUEST 1                             /* ARP Request             */
#define ARP_REPLY 2                               /* ARP Reply               */
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

#define MAXBYTES2CAPTURE 2048

void mac_eth(char MAC_str[13], char nic[10]);

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

    char current_ip[16];                          //The IP assigned to the NIC
    char my_mac[18];                              // The MAC of the NIC
    char mynew_octet[4];                          // The fourth octet of the address, we just use class C (CIDR or NOT)
    char originator_ip[16];                       // The IP of the ARP originator (sometimes me...)
    char destination_ip[16];                      // ARP destination, can be broadcast, (That's what we're interested in.)
    char current_sender_ip[16] = "0.0.0.0";       // The IP of sender we are currently configured to use (NEVER me...)
    char sender_ip[16] = "0.0.0.0";               // The IP of the most recently tested sender. (NEVER me...)
    char sender_mac[13];                          // The MAC addr of the sender gleaned from the ARP. (sometimes me...)
// The four IP octets that compose an address
    char soctet1[4], soctet2[4], soctet3[4], soctet4[4];
// The four IP octets that compose an address
    char toctet1[4], toctet2[4], toctet3[4], toctet4[4];
    int myhost_octet;                             // The numeric value of my host address
    int i=0;                                      // An iterator
    bpf_u_int32 netaddr=0, mask=0;                /* To Store network address and netmask   */
    struct bpf_program filter;                    /* Place to store the BPF filter program  */
    char errbuf[PCAP_ERRBUF_SIZE];                /* Error buffer                           */
    pcap_t *descr = NULL;                         /* Network interface handler              */
    struct pcap_pkthdr pkthdr;                    /* Packet information (timestamp,size...) */
    const unsigned char *packet=NULL;             /* Received raw data                      */
    arphdr_t *arpheader = NULL;                   /* Pointer to the ARP header              */
    memset(errbuf,0,PCAP_ERRBUF_SIZE);

    time_t tick = time (NULL);
    int threshold = 10;
    bool timer_enabled=false;

    int fd;
    struct ifreq ifr;
//Just set an IP address when we start the program to work around the issue below where packet capture won't start if your iface is dn or unconfigured
        std::stringstream ifcfg_stream;
        ifcfg_stream << "ifconfig " << argv[1] << " 1.1.1.1/24";
        const char* sed_cmd = ifcfg_stream.str().c_str();
        system(sed_cmd);

// Get My Current IP Address
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    strcpy(current_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
    printf("My IP: %s\n", current_ip);

// Get my NIC's MAC Address
    mac_eth(my_mac, argv[1]);
    printf("My MAC: %s\n", my_mac);

/* Open network device for packet capture */
    if ((descr = pcap_open_live(argv[1], MAXBYTES2CAPTURE, 0,  512, errbuf))==NULL)
    {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }

/* Look up info from the capture device. */
    if( pcap_lookupnet( argv[1] , &netaddr, &mask, errbuf) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", errbuf);
        exit(1);
    }

/* Compiles the filter expression into a BPF filter program */
    if ( pcap_compile(descr, &filter, "arp", 1, mask) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
        exit(1);
    }

/* Load the filter program into the packet capture device. */
    if (pcap_setfilter(descr,&filter) == -1)
    {
        fprintf(stderr, "ERROR: %s\n", pcap_geterr(descr) );
        exit(1);
    }

    while(1)                                      //Forever... As long as we have an IP address... Bad move could just be down?
    {
        packet = pcap_next(descr,&pkthdr);
        while( packet == NULL )                   //Check for new packets every second, if not found stay asleep
        {                                         //Sit and spin
// NIC's back, get his MAC, leave the mask alone!
            packet = pcap_next(descr,&pkthdr);
            sleep(1);                             // This old code's asleep till one.
        }

//Get my current IP again in case it changed, as it does often when testing this code.
        fd = socket(AF_INET, SOCK_DGRAM, 0);
        ifr.ifr_addr.sa_family = AF_INET;
        strncpy(ifr.ifr_name, argv[1], IFNAMSIZ-1);
        ioctl(fd, SIOCGIFADDR, &ifr);
        close(fd);
        strcpy(current_ip, inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));

        arpheader = (struct arphdr *)(packet+14); /* Point to the ARP header */

        printf("\n\nReceived Packet Size: %d bytes\n", pkthdr.len);
        printf("Hardware type: %s\n", (ntohs(arpheader->htype) == 1) ? "Ethernet" : "Unknown");
        printf("Protocol type: %s\n", (ntohs(arpheader->ptype) == 0x0800) ? "IPv4" : "Unknown");
        printf("Operation: %s\n", (ntohs(arpheader->oper) == ARP_REQUEST)? "ARP Request" : "ARP Reply");

/* If is Ethernet and IPv4, get package goodies */
        if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800)
        {
            printf("Sender MAC: ");

            char mac_part[3] = "";
            strcpy(sender_mac,"");
            for(i=0; i<6;i++)
            {
                printf("%02X ", arpheader->sha[i]);
                sprintf(mac_part,"%02X",arpheader->sha[i]);
                strcat(sender_mac,mac_part);
            }

            printf("\nOriginator IP: ");

            for(i=0; i<4;i++)
                printf("%d ", arpheader->spa[i]);

            sprintf(soctet1,"%d",arpheader->spa[0]);
            sprintf(soctet2,"%d",arpheader->spa[1]);
            sprintf(soctet3,"%d",arpheader->spa[2]);
            sprintf(soctet4,"%d",arpheader->spa[3]);

            strcpy(originator_ip,"");
            strcat(originator_ip, soctet1);
            strcat(originator_ip, ".");
            strcat(originator_ip, soctet2);
            strcat(originator_ip, ".");
            strcat(originator_ip, soctet3);
            strcat(originator_ip, ".");
            strcat(originator_ip, soctet4);

// Potential host octet, what it will be IF a change is made...
            if(arpheader->spa[3] < 254)
                myhost_octet = arpheader->spa[3]+1;
            else
                myhost_octet = arpheader->spa[3]-1;

            printf("\nDestination MAC: ");

            for(i=0; i<6;i++)
                printf("%02X ", arpheader->tha[i]);

            printf("\nDestination IP: ");

            strcpy(destination_ip,"");
            sprintf(toctet1,"%d",arpheader->tpa[0]);
            sprintf(toctet2,"%d",arpheader->tpa[1]);
            sprintf(toctet3,"%d",arpheader->tpa[2]);
            sprintf(toctet4,"%d",arpheader->tpa[3]);

            strcpy(destination_ip,"");
            strcat(destination_ip, toctet1);
            strcat(destination_ip, ".");
            strcat(destination_ip, toctet2);
            strcat(destination_ip, ".");
            strcat(destination_ip, toctet3);
            strcat(destination_ip, ".");
            strcat(destination_ip, toctet4);

            printf("%s\n", destination_ip);

//This occurs as long as the sender doesn't change.
//If we don't get any new arp challenges, this won't change.
            if(strcmp(sender_ip,current_sender_ip) == 0)
            {
                tick = time(NULL);
                printf("tick: %ld\n", tick);
            }

//If sender MAC NOT myself, AND sender IP HAS changed (since the last challenge was made)...
//                                                              ,this could be a toggle BACK to my current_sender_ip after an unsuccessful challenge
            if(strcmp(sender_mac,my_mac) != 0)
            {
                //system("arping -c 1 -q -b -I argv[1] HOST");
                printf("\nLast challenging connection: %s", originator_ip);
                printf("\nMy current connection is with: %s\n\n", current_sender_ip);
                printf("sender_ip diffs originator_ip:sender_mac != my_mac\n");
// If different, allow it to toggle sender_ip
// Let the challenger be introduced!
                strcpy(sender_ip,"");
                strcat(sender_ip, soctet1);
                strcat(sender_ip, ".");
                strcat(sender_ip, soctet2);
                strcat(sender_ip, ".");
                strcat(sender_ip, soctet3);
                strcat(sender_ip, ".");
                strcat(sender_ip, soctet4);

                if(strcmp(sender_ip,current_sender_ip) == 0)
                {                                 // Toggle back to my current_sender_ip, reset everything and go on like nothing ever happened.
                    printf("Yay, we are ourselves again!\n");
                }
                else
                {
// This was meant to stimulate the current sender into producing traffic...  It doesn't work...
//  And worse, we see this traffic and we get confused...  Uncomment when you are ready to fix this.
//   The benefits of this code is that this would work on a switched network without "flapping".
//                      printf("arping HOST @ %s\n", current_sender_ip);
//                      system("arping -c 1 -q -b -I argv[1] HOST");
//                      printf("Time: %ld\nTick: %ld\n", time(NULL), tick);

// Time tick will be used when the above is fixed.  For now, we just always change when we see an ARP change.
//                    if(time(NULL)-tick > threshold)
//                    {
                        printf("Challenge processed @: %ld\n", tick);
                        strcpy(sender_ip,"");
                        strcat(sender_ip, soctet1);
                        strcat(sender_ip, ".");
                        strcat(sender_ip, soctet2);
                        strcat(sender_ip, ".");
                        strcat(sender_ip, soctet3);
                        strcat(sender_ip, ".");
                        strcat(sender_ip, soctet4);
                        strcpy(current_sender_ip,"");
                        strcat(current_sender_ip, soctet1);
                        strcat(current_sender_ip, ".");
                        strcat(current_sender_ip, soctet2);
                        strcat(current_sender_ip, ".");
                        strcat(current_sender_ip, soctet3);
                        strcat(current_sender_ip, ".");
                        strcat(current_sender_ip, soctet4);

//This will update your static IP configuration (check the format and location of the network configuration file below)
//                        std::stringstream ifcfg_stream;
//                        ifcfg_stream << "sed -i 's|IPADDR=.*$|IPADDR=" << soctet1 << "." << soctet2 << "." << soctet3 << "." << myhost_octet << "|' " << "/etc/sysconfig/network-scripts/ifcfg-" << argv[1];
//                        const char* sed_cmd = ifcfg_stream.str().c_str();
//                        printf("\n\nsed_cmd: %s\n", sed_cmd);
//                        system(sed_cmd);

//Uncomment this is you want the network service restarted every time the mac changes...
//                        std::stringstream nic_stream;
//                        nic_stream << "ifdown " << argv[1] << " && ifup " << argv[1];
//                        const char* nic_toggle = nic_stream.str().c_str();
//                        printf("\n\nnic_toggle: %s\n", nic_toggle);
//                        system(nic_toggle);

// You might have to update all of these if your system no longer uses or supports the ifconfig command (boo).
//  Sigh, change makes me realize I'm getting old and grouchy...
// Also, this is another place where class C networks are hard coded... =)
                        std::stringstream ifcfg_stream;
                        ifcfg_stream << "ifconfig " << argv[1] << " " << soctet1 << "." << soctet2 << "." << soctet3 << "." << myhost_octet << "/24";
                        const char* ifcfg_toggle = ifcfg_stream.str().c_str();
                        printf("\n\nifcfg_toggle: %s\n", ifcfg_toggle);
                        system(ifcfg_toggle);


// You will always be able to talk to your directly connected computer by using the "HOST" alias.
//  Without having to know or keep track of the IP address.
                        char hosts_file[] = "/etc/hosts";
                        std::stringstream hosts_stream;
                        hosts_stream << "sed -i 's|.*HOST|" << originator_ip << " HOST|' " << hosts_file;
                        const char* sed_hosts = hosts_stream.str().c_str();
                        printf("\n\nsed_cmd: %s\n", sed_hosts);
                        system(sed_hosts);

                        packet=NULL;              //Set for next while loop
// This is just the end of the commented if(tick) {
//                    }
                }
            }
            packet=NULL;                          //Set for next while loop
        }
    }
    return 0;

}


void mac_eth(char MAC_str[13], char nic[10])
{
#define HWADDR_len 6
    int s,i;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, nic);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    for (i=0; i<HWADDR_len; i++)
        sprintf(&MAC_str[i*2],"%02X",((unsigned char*)ifr.ifr_hwaddr.sa_data)[i]);
    MAC_str[12]='\0';
}
