#include <iostream>
#include <pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include "pcap_header.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

int main()
{
    // track & name
    char track[] = "포렌식";
    char name[] = "정소연";

    printf("[bob5][%s]pcap_test[%s]\n\n", track, name);



    char * device;
    char * net;
    char * mask;

    char errbuf[PCAP_ERRBUF_SIZE]={0,};


    // device information
    device = pcap_lookupdev(errbuf);
    if (device == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Device              : %s\n",device);


    int temp;
    bpf_u_int32 netp;
    bpf_u_int32 maskp;

    temp=pcap_lookupnet(device, &netp, &maskp, errbuf);
    if(temp==-1){
        printf("%s\n", errbuf);
        exit(1);
    }


    struct in_addr net_addr;
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);

    if(net == NULL){
        perror("  [No Network Address]\n");
        exit(1);
    }
    printf("Network Address     : %s\n",net);


    struct in_addr mask_addr;
    mask_addr.s_addr = maskp;
    mask=inet_ntoa(mask_addr);

    if(mask == NULL)
    {
        perror("  [No Subnet Mask Address]\n");
        exit(1);
    }
    printf("Subnet Mask Address : %s\n",mask);


    // packet information
    pcap_t * packet;
    packet=pcap_open_live(device, 100, PROMISCUOUS, -1, errbuf);

    if(packet==NULL){
        printf("%s\n",errbuf);
        exit(1);
    }

    int temp2;
    while(1)
    {
        struct pcap_pkthdr * pkt_hdr;
        const u_char * pkt_data;

        temp2=pcap_next_ex(packet, &pkt_hdr, &pkt_data);

        if(temp2==0){
            continue;
        }
        else if(temp2==-1){
            printf("Error reading the packets: %s\n", pcap_geterr(packet));
            break;
        }

        struct ethhdr * ep = (struct ethhdr *)pkt_data;
        int i;


        printf("  Source      Mac Address : ");
        for(i=0;i<ETH_LENGTH-1;i++){
            printf("%.2x:",ep->h_source[i]);
        }
        printf("%.2x\n",ep->h_source[i]);

        printf("  Destination Mac Address : ");
        for(i=0;i<ETH_LENGTH-1;i++){
            printf("%.2x:",ep->h_dest[i]);
        }
        printf("%.2x\n",ep->h_dest[i]);


        if(ntohs(ep->h_proto) == 0x0800){ //if IPv4 packet
            struct ip4hdr * ipp = (struct ip4hdr *)(pkt_data + sizeof(ethhdr));

            printf("  Source      IP Address  : %s\n",inet_ntoa(ipp->ip_src));
            printf("  Destination IP Address  : %s\n",inet_ntoa(ipp->ip_dst));

            if(ipp->ip_p == 0x06){ //if TCP packet
                struct tcphdr * tcpp = (struct tcphdr *)(pkt_data + sizeof(ethhdr) + sizeof(ip4hdr));

                printf("  Source      Port        : %d\n",ntohs(tcpp->th_sport));
                printf("  Destination Port        : %d\n",ntohs(tcpp->th_dport));
            }
            else
                printf("  [NONE TCP pakcet]\n\n");
        }
        else{
            printf("  [NONE IP packet]\n\n");
        }
        break;
    }
    return 0;
}
