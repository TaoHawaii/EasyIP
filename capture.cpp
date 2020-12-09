#include <sstream.h>
#include <pcap.h>
#include "capture.h"

Capture::Capture()
{
  m_connectedNetHostSenderIp.clear();
  m_connectedNetHostSenderIp<<"0.0.0.0";
  m_potentialNetHostSenderIp.clear();
  m_potentialNetHostSenderIp<<"0.0.0.0";
	memset(m_pcapErrBuff,0,PCAP_ERRBUF_SIZE);
  m_netaddr=0;
  m_mask=0;
  capturedPacket=NULL;
}

int Capture::start(char* nicName)
{
  return ((m_pcapFileDescriptor = pcap_open_live(nicName,MAXBYTES2CAPTURE,0,512,m_pcapErrBuff)) == NULL) ? -1 : 0;
}

char* Capture::getErrBuff()
{
  return m_pcapErrBuff;
}

int Capture::lookupDeviceConfig(char* nicName)
{
  return pcap_lookupnet(nicName,&m_netaddr,&m_mask,m_pcapErrBuff);
}

int Capture::compileArpFilter()
{
  return pcap_compile(m_pcapFileDescriptor,&m_pcapFilter,"arp",1,m_mask);
}

pcap_t* Capture::getPcapInstanceDescriptor()
{
  return m_pcapFileDescriptor;
}

int Capture::loadCompiledFilter()
{
  return pcap_setfilter(m_pcapFileDescriptor,&m_pcapFilter);
}

void Capture::waitForeverForCapturedPacket()
{
  while (m_capturedPacket == NULL)
  {
    m_capturedPacket=pcap_next(m_pcapFileDescriptor,&m_pcapPacketHeader);
    sleep(1);//I don't like this.  We should implement interrupts.
//TODO; Implement interrupts...
  }
}

void Capture::getCapturedPacket()
{
  return m_capturedPacket;
}

struct pcap_pkthdr Capture::getPcapPacketHeader();
{
  return m_pcapPacketHeader;
}

void Capture::freeCapturedPacket()
{
  m_capturedPacket=NULL;
}

