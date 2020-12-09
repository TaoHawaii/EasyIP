#pragma once

#define HWADDR_len 6

class Nic
{
  private:
    std::stringstream m_ifcfg_stream;
    const char* m_interface;
    int m_fileDescriptor;
	  struct ifreq m_ifreqStruct;
    void setFileDescriptor(int fd);
    char m_currentIp[16];
    char m_MAC_str[13];
  public:
    Nic(const char* iface, const char* defaultIp);
    void setLocalNicDeviceIp(const char* IP);
    const char* getName();
    char* getCurrentIP();
    void queryLocalNicDeviceConfig();
    char* getMacAddress();
};
  
