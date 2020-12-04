#pragma once

#define MAXBYTES2CAPTURE 2048

class Capture
{
  private:
    pcap_t* m_pcapFileDescriptor;
    char m_pcapErrBuff[PCAP_ERBUF_SIZE];
    bpf_u_int32 m_netaddr, m_mask;
	  struct bpf_program m_pcapFilter;                    /* Place to store the BPF filter program  */
    const unsigned char* m_capturedPacket;
    struct pcap_pkthdr m_pcapPacketHeader;
  public:
    std::stringstream m_netPacketOriginatorIp;    // The IP of the ARP originator (sometimes me...)
    std::stringstream m_netPacketDestinationIp;   // ARP destination, can be broadcast, (That's what we're interested in.)
    std::stringstream m_connectedNetHostSenderIp; // The IP of sender we are currently configured to use (NEVER me...)
    std::stringstream m_potentialNetHostSenderIp; // The IP of the most recently tested sender. (NEVER me...)
    std::stringstream m_potentialNetHostSenderMac;// The MAC addr of the sender gleaned from the ARP. (sometimes me...)
    Capture(const char* iface);
    char* getNetPacketOriginatorIp();
    void setNetPacketOriginatorIp(char* IP);
    int start(char* nicName);
    char* getErrBuff();
    char* lookupDeviceConfig(char* nicName);
    char* compileArpFilter();
    pcap_t* getPcapInstanceDescriptor();
    char* loadCompiledFilter();
    void waitForeverForCapturedPacket();
    const unsigned char* getCapturedPacket();
    struct pcap_pkthdr getPcapPacketHeader();
    void freeCapturedPacket();
};
  
#endif
