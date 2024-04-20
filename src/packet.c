#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>

#include "ipk-sniffer.h"
#include "packet.h"


int get_devs(pcap_if_t** devsk){
    char errstring[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(devsk, errstring) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_findalldevs(): %s\n", errstring);
        return 1;
    }
    if(*devsk == NULL){
        fprintf(stdout, "No device was found\n");
        return 1;
    }
    return 0;
}

void print_interfaces(pcap_if_t *interfaces){
    pcap_if_t *temp = interfaces;
    while(temp != NULL){
        fprintf(stdout, "%s\n", temp->name);
        temp = temp->next;
    }
}

int check_interface(char* inface, pcap_if_t *interfaces){
    pcap_if_t *temp = interfaces;
    while(temp != NULL){
        if(strcmp(inface, temp->name) == 0){
            return 0;
        }
        temp = temp->next;
    }
    return 1;
}

pcap_t* get_handle(char* dev){
    char errstring[PCAP_ERRBUF_SIZE];
    bpf_u_int32 mask;
    bpf_u_int32 ip;
    pcap_t* handle;
    struct bpf_program filter;
    char filter_string[1000];
    memset(filter_string, 0, 1000);
    int i = 0;

    if(pcap_lookupnet(dev, &ip, &mask, errstring) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_lookupnet(): %s\n", errstring);
        return NULL;
    }

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errstring);
    if(handle == NULL){
        fprintf(stderr, "ERROR: pcap_open_live(): %s\n", errstring);
        return NULL;
    }

    if(DEF_FILTERS){
        if(DEF_TCP || DEF_UDP){
            sprintf(filter_string, "(");
            if(DEF_DST_PORT >= 0){
                if(DEF_SRC_PORT >= 0){
                    sprintf(&(filter_string[1]), "(dst port %d or src port %d) and ", DEF_DST_PORT, DEF_SRC_PORT);
                }else{
                    sprintf(&(filter_string[1]), "dst port %d and ", DEF_DST_PORT);
                }

            }else if(DEF_SRC_PORT >= 0){
                sprintf(&(filter_string[1]), "src port %d and ", DEF_DST_PORT);
            }

            if(DEF_TCP){
                if(DEF_UDP){
                    sprintf(&(filter_string[strlen(filter_string)]), "(tcp or udp)");
                }else{
                    sprintf(&(filter_string[strlen(filter_string)]), "tcp");
                }
            }else if(DEF_UDP){
                sprintf(&(filter_string[strlen(filter_string)]), "udp");
            }
            sprintf(&(filter_string[strlen(filter_string)]), ")");
        }
        if(DEF_ICPM4){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "icmp");
        }
        if(DEF_ICPM6){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "icmp6");
        }
        if(DEF_ARP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "arp");
        }
        if(DEF_NDP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "(icmp6 && ip6[40] == 135)");
        }
        if(DEF_IGMP){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string, "igmp");
        }
        if(DEF_MLD){
            if(strlen(filter_string) != 0) strcat(filter_string, " or ");
            strcat(filter_string,  "(icmp6 && ip6[40] == 131 || icmp6 && ip6[40] == 143)");
        }
    }

    #ifdef DEBUG
    printf("filter_string: %s\n", filter_string);
    #endif
    if(pcap_compile(handle, &filter, filter_string, 0, mask) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    if(pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }
    return handle;
}

int get_link_head_size(pcap_t* handle){
    int linktype;
    if ((linktype = pcap_datalink(handle)) == PCAP_ERROR) {
        fprintf(stderr, "ERROR: pcap_datalink(): %s\n", pcap_geterr(handle));
        return 0;
    }
    switch (linktype){
        case DLT_NULL:
            return 4;
    
        case DLT_EN10MB:
            return 14;
    
        case DLT_SLIP:
        case DLT_PPP:
            return 24;
    
        default:
            printf("Unsupported datalink of size %d\n", linktype);
            return 0;
    }
}

void handle_packet(unsigned char* user, const struct pcap_pkthdr* packet_head, const unsigned char* packet_ptr){
    struct ip* iphdr;
    struct icmp* icmphdr;
    struct tcphdr* tcphdr;
    struct udphdr* udphdr;

    packet_ptr =+ link_head_size;
    

}
