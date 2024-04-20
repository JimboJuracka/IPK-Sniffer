#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <pcap/pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <time.h>

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
    char filter_string[200];
    memset(filter_string, 0, 200);

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
    printf("INFO: filter_string: %s\n", filter_string);
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

void print_data(const char* data_ptr, int byte_offset, int size){
    printf("data: %s\n", data_ptr);
    char c;
    unsigned char m = 0xC0;
    int pn = size / byte_offset;
    int tn = byte_offset;
    if(size > 0){
        if(size % byte_offset > 0)
            pn++;
        
        for(int i = 0; i < pn; i++){
            if((i+1)*byte_offset > size){
                tn = size - i*byte_offset;
            }
            fprintf(stdout, "0x%04x ", i*byte_offset);
            for(int j = 0; j < tn; j++){
                fprintf(stdout, "%02x ", (unsigned char)data_ptr[i*byte_offset+j]);
                if(j == byte_offset/2 - 1){
                    fprintf(stdout, " ");
                }
            }
            if(tn != byte_offset){
                for(int g = 0; g < byte_offset - tn; g++){
                    fprintf(stdout, "   ");
                }
                if(tn < byte_offset/2){
                    fprintf(stdout, " ");
                }
            }
            fprintf(stdout, " ");
            for(int k = 0; k < tn; k++){
                c = data_ptr[i*byte_offset + k];
                if(c < 32 || c > 127){c = '.';}
                fprintf(stdout, "%c", c);
                if(k == byte_offset/2 - 1){
                    fprintf(stdout, " ");
                }
            }
            fprintf(stdout, "\n");
        }
    }
}

void handle_packet(unsigned char* user, const struct pcap_pkthdr* packet_head, const unsigned char* packet_ptr){
    struct ip* ip_hdr;
    struct icmp* icmp_hdr;
    struct tcphdr* tcp_hdr;
    struct udphdr* udp_hdr;
    struct igmp* igmp_hdr;
    struct tm* ts = localtime(&packet_head->ts.tv_sec);
    char timestamp[256];
    char dstmac[256];
    char srcmac[256];
    char dstip[256];
    char srcip[256];
    int frame_length = packet_head->len;
    int byte_offset;

    //reading time hurts
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%S", ts);
    sprintf(timestamp+strlen(timestamp), ".%06d", (int)packet_head->ts.tv_usec);
    strftime(timestamp+strlen(timestamp), sizeof(timestamp), "%z", ts);

    packet_ptr += link_head_size;
    ip_hdr = (struct ip*)packet_ptr;
    strcpy(dstip, inet_ntoa(ip_hdr->ip_src));
    strcpy(srcip, inet_ntoa(ip_hdr->ip_dst));

    switch(ip_hdr->ip_p){
        case IPPROTO_TCP:
            fprintf(stdout, "TCP:\n");
            fprintf(stdout, "timestamp: %s\n", timestamp);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            tcp_hdr = (struct tcphdr*)packet_ptr;
            fprintf(stdout, "src port %d\n",  ntohs(tcp_hdr->th_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(tcp_hdr->th_dport));
            byte_offset = 16;
            break;

        case IPPROTO_UDP:
            fprintf(stdout, "UDP:\n");
            fprintf(stdout, "timestamp: %s\n", timestamp);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            fprintf(stdout, "src IP: %s\n", srcip);
            fprintf(stdout, "dst IP: %s\n", dstip);
            udp_hdr = (struct udphdr*)packet_ptr;
            fprintf(stdout, "src port %d\n", ntohs(udp_hdr->uh_sport));
            fprintf(stdout, "dst port: %d\n", ntohs(udp_hdr->uh_dport));
            byte_offset = 16;
            break;

        case IPPROTO_ICMP:
            fprintf(stdout, "ICMPv4:\n");
            fprintf(stdout, "timestamp: %s\n", timestamp);
            fprintf(stdout, "frame length: %d bytes\n", frame_length);
            icmp_hdr = (struct icmp*)packet_ptr;
            fprintf(stdout, "Type: %d\n", icmp_hdr->icmp_type);
            fprintf(stdout, "Code: %d\n", icmp_hdr->icmp_code);
            byte_offset = 16;
            break;

        case IPPROTO_ICMPV6:
            fprintf(stdout, "ICMPv6:\n");
            fprintf(stdout, "timestamp: %s\n", timestamp);
            icmp_hdr = (struct icmp*)packet_ptr;
            fprintf(stdout, "Type: %d\n", icmp_hdr->icmp_type);
            fprintf(stdout, "Code: %d\n", icmp_hdr->icmp_code);
            byte_offset = 16;
            //TODO NDP & MLD packets
            break;

        case IPPROTO_IGMP:
            fprintf(stdout, "IGMP:\n");
            fprintf(stdout, "timestamp: %s\n", timestamp);
            igmp_hdr = (struct igmp*)packet_ptr;
            fprintf(stdout, "Type: %d\n", igmp_hdr->igmp_type);
            fprintf(stdout, "Code: %d\n", igmp_hdr->igmp_code);
            fprintf(stdout, "Group address: %s\n", inet_ntoa(igmp_hdr->igmp_group));
            byte_offset = 16;
            break;

        //TODO: ARP frames
    }
    fprintf(stdout, "\n");
    print_data(packet_ptr - link_head_size, byte_offset, packet_head->caplen);
    fprintf(stdout, "\n");
}
