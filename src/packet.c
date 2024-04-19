#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>

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
    char filter_string[500];
    memset(filter_string, 0, 500);

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
        //snprintf(filter_string, sizeof(filter_string), "ether");
        if(DEF_TCP){
            strcat(filter_string, " or tcp");
        }
        if(DEF_UDP){
            strcat(filter_string, " or udp");
        }
        if(DEF_DST_PORT != -1){
            snprintf(filter_string + strlen(filter_string), sizeof(filter_string) - strlen(filter_string), " && dst port %d", DEF_DST_PORT);
        }
        if(DEF_SRC_PORT >=0){
            snprintf(filter_string + strlen(filter_string), sizeof(filter_string) - strlen(filter_string), " && src port %d", DEF_DST_PORT);
        }
        if(DEF_ICPM4){
            strcat(filter_string, " or icpm");
        }
        if(DEF_ICPM6){
            strcat(filter_string, " or icmp6");
        }
        if(DEF_ARP){
            strcat(filter_string, " or arp");
        }
        if(DEF_NDP){
            strcat(filter_string, " or (icmp6 && ip6[40] == 135)");
        }
        if(DEF_IGMP){
            strcat(filter_string, " or igmp");
        }
        if(DEF_MLD){
            strcat(filter_string,  " or (icmp6 && ip6[40] == 131 || icmp6 && ip6[40] == 143)");
        }
        #ifdef DEBUG
        printf("filter_string: %s\n", filter_string);
        #endif
    }


    if(pcap_compile(handle, &filter, filter_string, 0, mask) == PCAP_ERROR){
        fprintf(stderr, "ERROR: pcap_compile(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    if(pcap_setfilter(handle, &filter) == PCAP_ERROR) {
        fprintf(stderr, "pcap_setfilter(): %s\n", pcap_geterr(handle));
        return NULL;
    }

    return handle;
}
