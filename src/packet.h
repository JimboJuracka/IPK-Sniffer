#ifndef IPK_PACKET
#define IPK_PACKET

int get_devs(pcap_if_t** devs);

void print_interfaces(pcap_if_t *interfaces);

int check_interface(char* inface, pcap_if_t *interfaces);

pcap_t* get_handle(char* dev);

#endif