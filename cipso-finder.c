/*
 * 1. We begin by determining which interface we want to sniff on
 * 2. Initialize pcap
 * 3. Create a rule set, "compile" it, and apply it
 * 4. Enter it's primary execution loop
 * 5. Close our session									<========
 * 
 * Look details here: https://www.ietf.org/archive/id/draft-ietf-cipso-ipsecurity-01.txt
 * 
*/

#include <stdlib.h>
#include <stdio.h>				// snprintf() 			
#include <stdbool.h>			// true, false
#include <unistd.h>				// getopt()
#include <arpa/inet.h>			// inet_ntoa(), inet_ntop() 
								// https://beej.us/guide/bgnet/html/single/bgnet.html#inet_ntopman
#include <net/ethernet.h>		// 'struct ether_header'
#include <netinet/ip.h>			// 'struct iphdr'
#include <netinet/ether.h>		// ether_ntoa()
#include <netinet/tcp.h>		// TCP header struct
#include <string.h>
#include <pcap.h>

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET  ETH_HLEN // =14  [linux/if_ether.h]

#ifdef DEBUG
	#define DL 
#else
	#define DL for(;0;)
#endif

#ifndef VERSION
	#define VERSION "unknown"
#endif


// Convert line to hex
void line2hex(unsigned char *str, int len, int columm) {
	int x;
	for(x=0; x < len; x++) {
		if( x>0 && x%columm == 0)
			printf("\n");
		printf("%02x ", str[x]);
	}
	printf("\n");
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

void
usage(char *usage_name) {
	
	printf("Version: %s \n", VERSION );
	printf("Usage: %s [-i interface] | [-f pcap_file] \n", usage_name);
	printf("   -i - listen on a real 'interface' (eth0, enp0s31f6 etc.) \n");
	printf("   -f - pcap file in tcpdump format for real 'interface' ('/tmp/foo.pcap')\n\n");
	exit(EXIT_FAILURE);
}


int main(int argc, char *argv[])
{
	pcap_t *handle;					// Session handle
	struct bpf_program cfe;			// The compiled filter expression
	char filter_exp[] = "ip";		// The filter expression
	bpf_u_int32 net;				// The net IP of our sniffing device
	bpf_u_int32 netmask;			// The netmask of our sniffing device
	struct pcap_pkthdr header;		// The header that pcap gives us
	//const u_char *packet;			// The actual packet

	char errbuf[PCAP_ERRBUF_SIZE];

	char *dev_to_listen = NULL;
	char *pcap_fname = NULL;
	int opt;
	

	// Get info from command line 
	if( argc == 1 )
		usage(argv[0]);
	
	opterr = 0;		// Supress 'getopt()' errors output
	while ((opt = getopt(argc, argv, "hi:f:")) != -1) {
		switch (opt) {
        case 'i':
			dev_to_listen = optarg;
		break;
		
		case 'f':
			pcap_fname = optarg;
		break;
		
		case 'h':
		case '?':
		default:
			usage(argv[0]);
		}
	}

	if( dev_to_listen != NULL && pcap_fname != NULL  ) usage(argv[0]);
	//---------------------------
	
	
	if( dev_to_listen != NULL )
	{
		if ( (handle = pcap_open_live(dev_to_listen, 65536, true, 1000, errbuf )) == NULL ) 
		{
			fprintf(stderr,"\n%s \n", errbuf);
			/* Free the device list */
			//pcap_freealldevs(alldevs);
			return -1;
		}
		printf("Listening on dev '%s'...\n",  dev_to_listen);


		if (pcap_lookupnet(dev_to_listen, &net, &netmask, errbuf) == -1) {
			fprintf(stderr, "Can't get netmask for device %s\n", dev_to_listen);
			net = 0;
			netmask = 0;
		} else {
			struct in_addr A1;
			char A1_str[16], A2_str[16];

			A1.s_addr = net;
			strcpy( A1_str, inet_ntoa(A1) );
		
			A1.s_addr = netmask;
			strcpy( A2_str, inet_ntoa(A1) );

			DL fprintf(stdout, "%s/%s for <%s> \n", A1_str, A2_str, dev_to_listen);
		}
	} else {
		if ( (handle = pcap_open_offline(pcap_fname, errbuf)) == NULL ) 
		{
			fprintf(stderr,"\n%s \n", errbuf);
			/* Free the device list */
			//pcap_freealldevs(alldevs);
			return -1;
		}
		printf("Open file '%s'...\n", pcap_fname );
	}	
	
	
	if (pcap_compile(handle, &cfe, filter_exp, 0, netmask) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return(2);
	 }
	 
	 if (pcap_setfilter(handle, &cfe) == -1) {
		 fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		 return(2);
	 }

	/* Grab a packet */
	//packet = pcap_next(handle, &header);
	pcap_loop(handle, -1, got_packet, NULL);
	

    pcap_close(handle);
    return 0;
}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	uint8_t ip_opt_type;
	uint8_t ip_opt_len;
	uint8_t	ip_opt_total_len;
	
	struct ether_header	*sniff_ether;	// Ethernet frame header struct pointer
	char tmp_dhost[20], tmp_shost[20];

	struct iphdr 		*sniff_ip;		// IP header struct pointer
	char tmp_daddr[20], tmp_saddr[20];
	
	struct tcphdr		*sniff_tcp;	// TCP header struct pointer
	uint16_t sport, dport;
	
	char *opts_p;					// Pointer to ALL IP header option
	
	char	 *cipso_hdr_p;			// Pointer to IP Option CIPSO address
	uint8_t	  cipso_hdr_len = 0;	// CIPSO total lenght <= 40 octets
	uint32_t  cipso_doi = 0;		// CIPSO DOI
	uint8_t	  cipso_curr_pos = 6;	// Position of current TAG
	
	uint8_t	  tag_type;		// TAG type [1, 2, 5]
	uint8_t   tag_len;		// TAG lenght
	uint8_t   tag_label;	// TAG sensivity label
	uint8_t	 *tag_p;		// Pointer to TAG start address
	
	char cats1[255] = {0};
	char cats2[255] = {0};
	char cats5[255] = {0};
	
	
	// Find Ehernet header offset (start at the beginning of the 'packet' string 'X')
	sniff_ether = (struct ether_header*)(packet);
	
	// Find IP header offset (X+ SIZE_ETHERNET [==14])
	sniff_ip = (struct iphdr *)(packet + SIZE_ETHERNET);
	
	// Find TCP header offset (X + SIZE_ETHERNET + {IP header length})
	sniff_tcp = (struct tcphdr *)(packet + SIZE_ETHERNET + (sniff_ip->ihl)*4 );
	
	if ( sniff_ip->ihl > 5 ) {
		DL printf("\nDetect packet with IP Options:  ");
		ip_opt_total_len = 4 * (sniff_ip->ihl - 5);
		DL printf("Total opts lenght == %d \n", ip_opt_total_len);

		opts_p = (char *)sniff_ip + 4 * 5; // Start point of IP options
		DL printf("  All IP  opts: "); DL line2hex(opts_p, ip_opt_total_len, 80);
		

		/* Let's find here the start point of CIPSO options */
		uint16_t z1 = 0, z2 = 0;
		while( 1 )
		{
			if( z1 >= ip_opt_total_len ) {
				DL printf("  Packet without CIPSO options \n");
				return;
			}
			ip_opt_type = (uint8_t)*(opts_p + z1);
			if( ip_opt_type == 0 ) {
				z1++;
				continue;
			}	
			ip_opt_len  = (uint8_t)*(opts_p + z1 +1);
			if ( ip_opt_type == 134 )	// CIPSO option = #134
				break;
				
			z1 += ip_opt_len;
			
			DL printf("-----> z1 = %d, ip_opt_len = %d \n", z1, ip_opt_len);
			
			if( z2++ == 3 )
				return;
		}
		
		/*
		 * Print common info about TCP/IP packate
		 */
		// Get MAC address and print it
		strcpy( tmp_dhost,  ether_ntoa( (struct ether_addr *)(sniff_ether->ether_dhost) ));
		strcpy( tmp_shost, 	ether_ntoa( (struct ether_addr *)(sniff_ether->ether_shost) ));

	
		// Get IP address and print it
		inet_ntop(AF_INET, &(sniff_ip->saddr), tmp_saddr, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(sniff_ip->daddr), tmp_daddr, INET_ADDRSTRLEN);

			
		// Get Source and Destination port from TCP header
		sport = ntohs( sniff_tcp->th_sport );
		dport = ntohs( sniff_tcp->th_dport );

		
		printf("\n%s:%d [%s] ----- %s:%d [%s] \n",
					tmp_saddr,sport,tmp_shost,   tmp_daddr, dport,tmp_dhost);
		
		
		/* Let's imagine that we found CIPSO option among others*/
		cipso_hdr_p = opts_p + z1;
		cipso_hdr_len = (uint8_t)*(cipso_hdr_p + 1);

			
		cipso_doi = ntohl(  *(uint32_t*)(cipso_hdr_p+2) );
		DL printf("  CIPSO: 134,  DOI: %d,  Len: %d \n", cipso_doi, cipso_hdr_len);
		if ( cipso_hdr_len <= 6 ) {	// CIPSO header len == 6
			printf("===> CIPSO lenght too small to have TAGs\n");
			return;
		}

		/* 
		 * Find all TAGs and decode ones
		 */
		for ( int z = 1; z <=10; z++) {
			tag_p = cipso_hdr_p + cipso_curr_pos;
				
			tag_type  = (uint8_t)*(tag_p + 0);
			tag_len   = (uint8_t)*(tag_p + 1);
			tag_label = (uint8_t)*(tag_p + 3);
				
			
			DL printf("  "); DL line2hex(tag_p, tag_len, tag_len);

			// TAG decode here
			switch( tag_type ) {
			case 1:
			{
				uint8_t x, x2;
				
				for ( x=0; x < tag_len - 4; x++)
				{
					for ( x2 = 0; x2 <= 7; x2++) {
						if ( (*(tag_p + 4 + x) & 0x80 >> x2) != 0 )	{ // 0x80 == 1000 0000
							char tmp_ch[10] = {0};
							snprintf(tmp_ch, sizeof tmp_ch, "%d,", x2 + x*8);
							strncat(cats1, tmp_ch, sizeof tmp_ch); 
						}
					}
				}
				
				if( cats1[ strlen(cats1) - 1 ] == ',' )
						cats1[ strlen(cats1) - 1 ] = '\0';
						
				printf("   DOI: %d,  TAG: %d,  Sensitivity: %d,  Categories: %s \n",
											cipso_doi, tag_type, tag_label, cats1);
			}
			break;
				
			case 2:
			{
				uint16_t tmp_d;
				uint8_t x;
				
				for ( x=4; x < tag_len; x += 2)
				{
					tmp_d = ntohs( *((uint16_t*)(tag_p + x)) );
					
					char tmp_ch[10] = {0};
					snprintf(tmp_ch, sizeof tmp_ch, "%d,", tmp_d);
					strncat(cats2, tmp_ch, sizeof tmp_ch); 
				}
				
				if( cats2[ strlen(cats2) - 1 ] == ',' )
						cats2[ strlen(cats2) - 1 ] = '\0';
				
				printf("   DOI: %d,  TAG: %d,  Sensitivity: %d,  Categories: %s \n",
											cipso_doi, tag_type, tag_label, cats2);
			}
			break;
				 
			case 5:
			{
				uint16_t tmp_top, tmp_bottom;
				uint8_t x;
				
				DL printf("   tag_len = %d \n", tag_len );
				DL printf("   ");
				DL line2hex((tag_p + 4), tag_len - 4, 80);
				
				for ( x=4; x < tag_len; x += 4)
				{
					tmp_top = ntohs( *((uint16_t*)(tag_p + x)) );
					if( x + 2 >= tag_len )
						tmp_bottom = 0;
					else
						tmp_bottom = ntohs( *((uint16_t*)(tag_p + x + 2)) );
						
					if( tmp_top != tmp_bottom ) {
						char tmp_ch[15] = {0};	// 63000-64000 == 12 chars MAX
						snprintf(tmp_ch, sizeof tmp_ch, "%d-%d,", tmp_top, tmp_bottom);
						strncat(cats5, tmp_ch, sizeof tmp_ch);
					} else {
						char tmp_ch[10] = {0};	// 63000 == 6 chars MAX
						snprintf(tmp_ch, sizeof tmp_ch, "%d,", tmp_top);
						strncat(cats5, tmp_ch, sizeof tmp_ch);
					}
				}
				
				if( cats5[ strlen(cats5) - 1 ] == ',' )
						cats5[ strlen(cats5) - 1 ] = '\0';
						
				printf("   DOI: %d,  TAG: %d,  Sensitivity: %d,  Categories: %s \n",
											cipso_doi, tag_type, tag_label, cats5);
			}
			break;
				  
			default:
				printf("   Unknown TAG type = %d \n", tag_type);
			}
				

			cipso_curr_pos += tag_len;
			if(  cipso_curr_pos >= cipso_hdr_len )
				return;
		}
	}
}


// printf ("%c", ( (*tag_p & 1<<z) == 0) ? '0' : '1' );

