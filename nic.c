#include <stdlib.h>//std::system()
#include <string.h>//str(),c_str()
#include <sstream>//std::stringstream
#include <sys/socket.h>//socket(AF_INET,SOCK_DGRAM)
#include <sys/ioctl.h>
#include <net/if.h>//struct ifreq
#include "nic.h"

Nic::Nic(const char* iface, const char* defaultIp):m_interface(iface)
{
  m_ifcfg_stream.clear();
  m_fileDescriptor = -1;
	m_ifreqStruct.ifr_addr.sa_family = AF_INET;
	strncpy(m_ifreqStruct.ifr_name, m_interface, IFNAMSIZ-1);
  setLocalNicDevIp(defaultIp);
}

void Nic::setLocalNicDeviceIp(const char* IP)
{
  m_ifcfg_stream << "ifconfig" << ' ' << m_interface << ' ' << m_IP<<"/24";
  system((const char*) m_ifcfg_stream.str().c_str());
}

void Nic::setFileDescriptor(int fd)
{
  m_fileDescriptor = fd;
}

char* Nic::getName()
{
  return m_interface;
}

char* Nic::getCurrentIP()
{
  return m_current_ip[];
}

void Nic::queryLocalNicDeviceConfig()
{
  setFileDescriptor(socket(AF_INET, SOCK_DGRAM, 0));//filedescriptor handle to NIC device
	ioctl(m_fileDescriptor, SIOCGIFADDR, &m_ifreqStruct);//set ioctl/s from our ifreq struct
  //Save the MAC address
	for (int i=0; i<HWADDR_len; i++)
	    sprintf(&m_MAC_str[i*2],"%02X",((unsigned char*)m_ifreqStruct.ifr_hwaddr.sa_data)[i]);
	m_MAC_str[12]='\0';
  close(m_fileDescriptor);
  //save the IP address
	strcpy(m_current_ip, inet_ntoa(((struct sockaddr_in *)&m_ifreqStruct.ifr_addr)->sin_addr));
}

void Nic::getMacAddress()
{
  return m_MAC_str[];
}

