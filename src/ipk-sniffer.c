#include <stdio.h>
#include <getopt.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#include <pcap/pcap.h>

#include "ipk-sniffer.h"
#include "packet.h"

int packet_num;
int link_head_size;
pcap_t *handle = NULL;

char* DEF_INTERFACE = NULL;
int INTERFACE_USED_FLAG = 0;
int DEF_TCP = 0;
int DEF_UDP = 0;
int DEF_ANY_PORT = -1;
int DEF_DST_PORT = -1;
int DEF_SRC_PORT = -1;
int DEF_ICPM4 = 0;
int DEF_ICPM6 = 0;
int DEF_ARP = 0;
int DEF_NDP = 0;
int DEF_IGMP = 0;
int DEF_MLD = 0;
int DEF_N = 1;
int DEF_FILTERS = 0;
char* HELP_MSG =
"Usage:\n"
"./ipk-sniffer [-i interface | --interface interface] {-p|--port-source|--port-destination port [--tcp|-t] [--udp|-u]} [--arp] [--icmp4] [--icmp6] [--igmp] [--mld] {-n num} [-help|-h]\n"
"\n"
"Options:\n"
"-h, --help                             Displays this message.\n"
"-n num                                 Specifies the number of packets to display.\n"
"-i interface, --interface interface    Choose network interface.\n"
"-t, --tcp                              Will display TCP segments.\n"
"-u, --udp                              Will display UDP segments.\n"
"-p port                                Extends previous two parameters to filter TCP/UDP based on port number.\n"
"--port-destination port                Extends previous two parameters, the given port can occur in destination part of TCP/UDP headers.\n"
"--port-source port                     Extends previous two parameters, the given port can occur in source part of TCP/UDP headers.\n"
"--icmp4                                Will display only ICMPv4 packets.\n"
"--icmp6                                Will display only ICMPv6 packets.\n"
"--arp                                  Will display only ARP frames.\n"
"--ndp                                  Will display only NDP packets, subset of ICMPv6.\n"
"--igmp                                 Will display only IGMP packets.\n"
"--mld                                  Will display only MLD packets, subset of ICMPv6.\n"
;

int main(int argc, char** argv){
    pcap_if_t *devs = NULL;
    int optc;
    char* endptr = NULL;
    errno = 0;
    static struct option arg_options[] = {
        {"interface",           required_argument,  0, 'i'},
        {"tcp",                 no_argument,        0, 't'},
        {"udp",                 no_argument,        0, 'u'},
        {"port-destination",    required_argument,  0, 'd'},
        {"port-source",         required_argument,  0, 's'},
        {"icmp4",               no_argument,        0, '4'},
        {"icmp6",               no_argument,        0, '6'},
        {"arp",                 no_argument,        0, 'a'},
        {"ndp",                 no_argument,        0, 'N'},
        {"igmp",                no_argument,        0, 'g'},
        {"mld",                 no_argument,        0, 'm'},
        {"help",                no_argument,        0, 'h'},
        {0,                     0,                  0, 0}
    };

    while((optc = getopt_long(argc, argv, ":i:tup:n:h", arg_options, NULL)) != -1){
        switch(optc){
            case -1:
                break;
            
            case 'i':
                //TODO: validate interface or exit with error
                if(DEF_INTERFACE != NULL){

                }
                DEF_INTERFACE = optarg;
                INTERFACE_USED_FLAG = 1;
                #ifdef DEBUG
                printf("option i with value '%s'\n", optarg);
                #endif
                continue;

            case 't':
                DEF_TCP = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option t\n");
                #endif
                continue;

            case 'u':
                DEF_UDP = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option u\n");
                #endif
                continue;

            case 'p':
                if(DEF_DST_PORT >= 0 || DEF_SRC_PORT >= 0){
                    fprintf(stderr, "Excessive port arguments\n");
                    exit(EXIT_FAILURE);
                }
                DEF_ANY_PORT = strtol(optarg, &endptr, 0);
                if(DEF_ANY_PORT < 0 || errno != 0 || !(endptr == NULL ||  *endptr == '\0')){
                    fprintf(stderr, "Invalid argument '%s' for option '%c'\n", optarg, optc);
                    exit(EXIT_FAILURE);
                }
                #ifdef DEBUG
                printf("option p with value '%s'\n", optarg);
                #endif
                continue;

            case 'd':
                if(DEF_ANY_PORT >= 0){
                    fprintf(stderr, "Excessive port arguments\n");
                    exit(EXIT_FAILURE);
                }
                DEF_DST_PORT = strtol(optarg, &endptr, 0);
                if(DEF_DST_PORT < 0 || errno != 0 || !(endptr == NULL ||  *endptr == '\0')){
                    fprintf(stderr, "Invalid argument '%s' for option '%c'\n", optarg, optc);
                    exit(EXIT_FAILURE);
                }
                #ifdef DEBUG
                printf("option d with value '%s'\n", optarg);
                #endif
                continue;

            case 's':
                if(DEF_ANY_PORT >= 0){
                    fprintf(stderr, "Excessive port arguments\n");
                    exit(EXIT_FAILURE);
                }
                DEF_SRC_PORT = strtol(optarg, &endptr, 0);
                if(DEF_SRC_PORT < 0 || errno != 0 || !(endptr == NULL ||  *endptr == '\0')){
                    fprintf(stderr, "Invalid argument '%s' for option '%c'\n", optarg, optc);
                    exit(EXIT_FAILURE);
                }
                #ifdef DEBUG
                printf("option s with value '%s'\n", optarg);
                #endif
                continue;

            case '4':
                DEF_ICPM4 = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option 4\n");
                #endif
                continue;

            case '6':
                DEF_ICPM6 = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option 6\n");
                #endif
                continue;

            case 'a':
                DEF_ARP = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option a\n");
                #endif
                continue;

            case 'N':
                DEF_NDP = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option N\n");
                #endif
                continue;

            case 'g':
                DEF_IGMP = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option g\n");
                #endif
                continue;

            case 'm':
                DEF_MLD = 1;
                DEF_FILTERS = 1;
                #ifdef DEBUG
                printf("option m\n");
                #endif
                continue;

            case 'n':
                DEF_N = strtol(optarg, &endptr, 0);
                if(errno != 0 || !(endptr == NULL ||  *endptr == '\0')){
                    fprintf(stderr, "Invalid argument '%s' for option '%c'\n", optarg, optc);
                    exit(EXIT_FAILURE);
                }
                #ifdef DEBUG
                printf("option n with value '%s'\n", optarg);
                #endif
                continue;

            case 'h':
                fprintf(stdout, "%s", HELP_MSG);
                exit(EXIT_SUCCESS);

            case ':':
                if(optopt == 'i'){
                    INTERFACE_USED_FLAG = 1;
                    #ifdef DEBUG
                    printf("option i without value\n");
                    #endif
                }else{
                    fprintf(stderr, "Option '%c' requires an argument\n", optopt);
                    exit(EXIT_FAILURE);
                }
                continue;

            case '?':
                fprintf(stderr, "Invalid option '%c'\n", optopt);
                exit(EXIT_FAILURE);

            default:
                fprintf(stderr, "ERROR: getopt_long\n");
                exit(EXIT_FAILURE);
        }

    }
    if(get_devs(&devs)){
        exit(EXIT_FAILURE);
    }
    if(argc == 1 || (argc == 2 && DEF_INTERFACE == NULL && INTERFACE_USED_FLAG)){
        print_interfaces(devs);
        pcap_freealldevs(devs);
        exit(EXIT_SUCCESS);
    }
    if(DEF_INTERFACE == NULL){
        fprintf(stderr, "Interface not specified. Use '-i interface' or '--interface interface'\n");
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    if(check_interface(DEF_INTERFACE, devs)){
        fprintf(stderr, "Interface '%s' not found\n", DEF_INTERFACE);
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    if(optind != argc){
        fprintf(stderr, "Unknown option '%s'\n", argv[optind]);
        pcap_freealldevs(devs);
        exit(EXIT_FAILURE);
    }
    pcap_freealldevs(devs);



    handle = get_handle(DEF_INTERFACE);
    if(handle == NULL){
        exit(EXIT_FAILURE);
    }

    if(pcap_loop(handle, DEF_N, handle_packet, NULL) < 0){
        fprintf(stderr, "ERROR: pcap_loop: %s", pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    #ifdef DEBUG
    printf("ende\n");
    #endif
    exit(EXIT_SUCCESS);
}