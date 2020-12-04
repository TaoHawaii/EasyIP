#pragma once

#define HWADDR_len 6

class Nic
{
  private:
    std::stringstream m_ifcfg_stream;
    const char* m_interface;
    int m_fileDescriptor;
	  struct ifreq m_ifreqStruct;
    void setFileDescriptor;
    char current_ip[16];
    char m_MAC_str[13];
  public:
    Nic(const char* iface);
    void setLocalNicDeviceIp(const char* IP);
    char* getName();
    char* getCurrentIP();
    void queryLocalNicDeviceConfig();
    char* getMacAddress();
};
  
#endif
