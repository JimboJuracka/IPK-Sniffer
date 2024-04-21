#ifndef IPK_PACKET
#define IPK_PACKET

int get_devs(pcap_if_t** devs);

void print_interfaces(pcap_if_t *interfaces);

int check_interface(char* inface, pcap_if_t *interfaces);

pcap_t* get_handle(char* dev);

void print_data(const unsigned char* data_ptr, int byte_offset, int size);

void handle_packet(unsigned char* user, const struct pcap_pkthdr* packet_head, const unsigned char* ptr);

void stop_capture();

#endif