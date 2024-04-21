#ifndef IPK_SNIFFER
#define IPK_SNIFFER

/*      Program variables       */

extern char* DEF_INTERFACE; // user given interface name
extern int DEF_FILTERS;     // True if filter is enabled
extern int DEF_TCP;         // TCP filter
extern int DEF_UDP;         // UDP filter
extern int DEF_ANY_PORT;    // Port (dst or src)
extern int DEF_DST_PORT;    // Destination port
extern int DEF_SRC_PORT;    // Source port
extern int DEF_ICPM4;       // ICMPv4 filter
extern int DEF_ICPM6;       // ICPMv6 filter
extern int DEF_ARP;         // ARP frames filter
extern int DEF_NDP;         // NDP filter
extern int DEF_IGMP;        // IGMP filter
extern int DEF_MLD;         // MLP filter
extern int DEF_N;           // nuber of packets to print

extern pcap_t *handle;

#endif