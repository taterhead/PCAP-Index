/**
 * Most of the first part of this is copied directly from sniffex.c, www.tcpdump.org/sniffex.c
 */
 
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
        u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
        u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
        u_short ether_type;                     /* IP? ARP? RARP? etc */
};


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
        u_short th_sport;               /* source port */
        u_short th_dport;               /* destination port */
        tcp_seq th_seq;                 /* sequence number */
        tcp_seq th_ack;                 /* acknowledgement number */
        u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
        u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
        #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
        u_short th_win;                 /* window */
        u_short th_sum;                 /* checksum */
        u_short th_urp;                 /* urgent pointer */
};

struct pcap_pkthdr32 {
	// Need to make sure it's in the 32 bit format...
	bpf_u_int32 tv_s;	/* time stamp */
	bpf_u_int32 tv_us;
	bpf_u_int32 caplen;	/* length of portion present */
	bpf_u_int32 len;	/* length this packet (off wire) */
};

/**
 * Get MAC as an integer
 */
unsigned long long get_mac_int(u_char *ether_addr){

	/* hex */
	u_char * ch;
	int i = 0;
	unsigned long long int mac_int = 0;
	ch = ether_addr;
	for(i = 0; i < 6; i++) {
		// printf("%02x ", *ch);
		mac_int = mac_int << 8;
		mac_int += (unsigned long long int)*ch;
		ch++;
	}
	// printf("mac val %Lu ", mac_int);
	
	return mac_int;
	
}


// Code will probably be messy... then cleaned up later. We all say that, right?
int main(int argc, char **argv)
{
	// variables
	char *pcap_fname = NULL;
	unsigned long long int offset = 0;
	FILE *pcap_f = NULL;
	struct pcap_pkthdr32 *pkthdr = malloc(sizeof(struct pcap_pkthdr));
	unsigned long long int pcap_f_size = 0;
	
	
	
	// Check for args
	if (argc == 2) {
		pcap_fname = argv[1];
		
	}
	else {
		// Error
		fprintf(stderr, "ERROR: Wrong options\n\n");
		exit(EXIT_FAILURE);
	}

	
	// Open PCAP file
	pcap_f = fopen(pcap_fname, "rb");
	
	if (pcap_f == NULL) {
		fprintf(stderr, "ERROR opening pcap file");
		exit(1);
	}
	
	// Get size of file
	fseek(pcap_f, 0, SEEK_END);
	pcap_f_size = ftell(pcap_f);
	rewind(pcap_f);
	
	// Skip pcap file header
	fseek(pcap_f, 24, SEEK_SET);
	
	// printf("Total file size: %u \n", pcap_f_size);
	
	while (!feof(pcap_f)) {
		unsigned int data_len = 0;
		unsigned char *pkt_data = NULL;
		struct sniff_ethernet *ether_hdr = NULL;
		struct iphdr *ip_hdr = NULL;
		struct ip6_hdr *ipv6_hdr = NULL;
		struct tcphdr *tcp_hdr = NULL;
		struct udphdr *udp_hdr = NULL;
		
		// pkt info
		unsigned int src_hh = 0;
		unsigned int src_h = 0;
		unsigned int src_l = 0;
		unsigned long long int src_ll = 0;
		
		unsigned int dst_hh = 0;
		unsigned int dst_h = 0;
		unsigned int dst_l = 0;
		unsigned long long int dst_ll = 0;
		unsigned int ether_type = 0;
		unsigned int ip_proto = 0;
		unsigned int sport = 0;
		unsigned int dport = 0;
		
		
		// update the offset var
		offset = ftell(pcap_f);
		
		// read the first pkt header data in
		fread(pkthdr, 16, 1, pcap_f);
		
		
		data_len = pkthdr->caplen + 16;
		
		// allocate memory and read in pkt data
		pkt_data = malloc(data_len - 16);
		fread(pkt_data, data_len - 16, 1, pcap_f);
		ether_hdr = (struct sniff_ethernet*)pkt_data;
		
		// By default, set src/dst to ethernet hdr
		src_ll = get_mac_int(ether_hdr->ether_shost);
		dst_ll = get_mac_int(ether_hdr->ether_dhost);
		
		// Now check to see if it's an IP pkt
		if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IP) {
			unsigned int size_ip = 0;
			ether_type = ETHERTYPE_IP;
			ip_hdr = (struct iphdr*)(pkt_data + SIZE_ETHERNET);
			src_ll = ntohl(ip_hdr->saddr);
			dst_ll = ntohl(ip_hdr->daddr);
			ip_proto = ip_hdr->protocol;
			
			size_ip = ip_hdr->ihl*4;
			
			// check for TCP or UDP
			if (ip_proto == IPPROTO_TCP) {				
				tcp_hdr = (struct tcphdr*)(pkt_data + SIZE_ETHERNET + size_ip);
				
				sport = ntohs(tcp_hdr->source);
				dport = ntohs(tcp_hdr->dest);
			}
			
			else if (ip_proto == IPPROTO_UDP) {
				udp_hdr = (struct udphdr*)(pkt_data + SIZE_ETHERNET + size_ip);
				
				sport = ntohs(udp_hdr->source);
				dport = ntohs(udp_hdr->dest);
				
			}
			
			// don't need a final else - values already set to 0 if these aren't found
			
		}
		
		// if IPv6...
		else if (ntohs(ether_hdr->ether_type) == ETHERTYPE_IPV6) {
			ipv6_hdr = (struct ip6_hdr*)(pkt_data + SIZE_ETHERNET);
			ether_type =  ETHERTYPE_IPV6;
			
			// now need to extract all the parts of the ipv6 address
			// pointer and dereferencing fun...
			src_hh = ntohl(((unsigned int*)&(ipv6_hdr->ip6_src))[0]);
			src_h = ntohl(((unsigned int*)&(ipv6_hdr->ip6_src))[1]);
			src_l = ntohl(((unsigned int*)&(ipv6_hdr->ip6_src))[2]);
			src_ll = ntohl(((unsigned int*)&(ipv6_hdr->ip6_src))[3]);
			
			dst_hh = ntohl(((unsigned int*)&(ipv6_hdr->ip6_dst))[0]);
			dst_h = ntohl(((unsigned int*)&(ipv6_hdr->ip6_dst))[1]);
			dst_l = ntohl(((unsigned int*)&(ipv6_hdr->ip6_dst))[2]);
			dst_ll = ntohl(((unsigned int*)&(ipv6_hdr->ip6_dst))[0]);
			
			ip_proto = ipv6_hdr->ip6_ctlun.ip6_un1.ip6_un1_nxt;
			
			// Check for TCP or UDP. 
			if(ip_proto == IPPROTO_TCP) {
				tcp_hdr = (struct tcphdr*)(pkt_data + SIZE_ETHERNET + sizeof(struct ip6_hdr));
				
				sport = ntohs(tcp_hdr->source);
				dport = ntohs(tcp_hdr->dest);
			}
			
			else if (ip_proto == IPPROTO_UDP) {
				udp_hdr = (struct udphdr*)(pkt_data + SIZE_ETHERNET + sizeof(struct ip6_hdr));
				
				sport = ntohs(udp_hdr->source);
				dport = ntohs(udp_hdr->dest);
			}
			
			
		}
		
		
		// printf("Test output:");
		// printf("Offset: %u TS: %u %u CAPLEN: %u SRC: %u,%u,%u,%Lu, %d;  DST: %u,%u,%u,%Lu, %d \n", offset, pkthdr->tv_s, pkthdr->tv_us, pkthdr->caplen, src_hh,src_h,src_l,src_ll, sport, dst_hh,dst_h,dst_l,dst_ll, dport );
		printf("%u,%u,%u,%u,%u,%u,%u,%Lu,%u,%u,%u,%u,%Lu,%u,%s,%Lu,%u\n", pkthdr->tv_s, pkthdr->tv_us, ether_type, ip_proto, src_hh, src_h, src_l, src_ll, sport, dst_hh, dst_h, dst_l, dst_ll, dport, pcap_fname, offset, data_len);
		
		// skip to the next pkt header
		//fseek(pcap_f, data_len, SEEK_CUR);
		
		// free up memory
		free(pkt_data);
		
	}
	
	// close the file and others
	fclose(pcap_f);
	free(pkthdr);
	return 0;
	
}
