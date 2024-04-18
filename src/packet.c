#include <stdio.h>
#include <pcap/pcap.h>
#include <string.h>
#include <stdlib.h>

//#include "ipk-sniffer.h"
#include "packet.h"

int get_devs(pcap_if_t* devs){
    char errstring[PCAP_ERRBUF_SIZE];
    if(pcap_findalldevs(&devs, errstring)){
        fprintf(stderr, "ERROR: pcap_findalldevs(): %s\n", errstring);
        return 1;
    }
    if(devs == NULL){
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
        if(strcmp(inface, temp->name)){
            return 0;
        }
        temp = temp->next;
    }
    return 1;
}
