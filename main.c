#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>  
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <linux/filter.h>
#include <sys/ioctl.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <sys/select.h>

#ifdef DEBUG
    #define DP
#else
    #define DP for(;0;)
#endif

#ifndef VERSION
    #define VERSION "unknown"
#endif

#define BUFF_SIZE	2048

// Convert dump to hex
void memdump2hex( void*, uint16_t, uint8_t);

ssize_t  get_ethernet_info(unsigned char *, uint16_t, uint16_t *);
ssize_t  get_ip_info(unsigned char *, uint16_t, uint16_t *);
ssize_t  get_udp_info(unsigned char *, uint16_t );
ssize_t  get_tcp_info(unsigned char *, uint16_t );

ssize_t cipso_payload_decode(unsigned char *, uint16_t);

void
usage(char *usage_name) {

    printf("Version: %s \n", VERSION );
    //printf("Usage: %s [-i interface] | [-f pcap_file] \n", usage_name);
    printf("Usage: %s [-i interface] \n", usage_name);
    printf("   -i - listen on a real 'interface' (eth0, enp0s31f6 etc.) \n");
    //printf("   -f - pcap file in tcpdump format for real 'interface' ('/tmp/foo.pcap')\n\n");
    exit(-1);
}

struct sock_filter BPF_code[]= {
    { 0x28,  0,  0, 0x0000000c },
    { 0x15,  0,  5, 0x00000800 },
    { 0x01,  0,  0, 0x0000000e },
    { 0x50,  0,  0, 0000000000 },
    { 0x25,  0,  2, 0x00000045 },
    { 0x25,  1,  0, 0x0000004f },
    { 0x06,  0,  0, 0xffffffff },
    { 0x06,  0,  0, 0000000000 },
  };

struct cipso_type {
    uint8_t tag_n;
    uint8_t slevel;
    char cats[1024];
};

struct packate_info {
    char dst_mac[17+1];
    char src_mac[17+1];

    char src_ip[15+1];
    char dst_ip[15+1];

    uint8_t ip_proto;

    uint16_t src_port;
    uint16_t dst_port;

    uint16_t doi;
    struct cipso_type cipso_t1;
    struct cipso_type cipso_t2;
    struct cipso_type cipso_t5;
} pkt_info;


int main(int argc, char *argv[]) {
    DP printf("%s() \n", __func__);

    int sock_fd, sig_fd;
    //int sig_fd;
    int ret_select;

    /* We will handle SIGTERM and SIGINT. */
    sigset_t sig_mask;
    sigemptyset (&sig_mask);
    sigaddset (&sig_mask, SIGTERM);
    sigaddset (&sig_mask, SIGINT);

	unsigned char buffer[BUFF_SIZE];
	short int old_ifr_flags;

	struct ifreq ethreq;

	struct sock_fprog Filter = {
        .len = 8,
        .filter = BPF_code
    };

	/*  Exec parameters parsing  */
    char *ifname = NULL;
    // char *pcap_fname = NULL;
    int opt;
    opterr = 0;		// Supress 'getopt()' errors output

    // Get info from command line
    while ((opt = getopt(argc, argv, "hi:f:")) != -1) {
        switch (opt) {
            case 'i':
                ifname = optarg;
            break;

            //case 'f':
            //    pcap_fname = optarg;
            //break;

            case 'h':
            case '?':
            default:
                usage(argv[0]);
        }
    }

    if( ifname == NULL )
        usage(argv[0]);


    /* Block the signals that we handle using signalfd(), so they don't
    * cause signal handlers or default signal actions to execute. */
    if (sigprocmask(SIG_BLOCK, &sig_mask, NULL) < 0) {
        perror ("sigprocmask");
        return 1;
    }

    /* Create a file descriptor from which we will read the signals. */
    sig_fd = signalfd (-1, &sig_mask, 0);
    if (sig_fd < 0) {
        perror ("signalfd");
        return 1;
    }


    if( (sock_fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) == -1)
	{
		perror("socket");
		exit(1);
	}


	/* Set the network card in promiscuos mode */
	strcpy(ethreq.ifr_name, ifname);

	if( ioctl(sock_fd, SIOCGIFFLAGS, &ethreq) == -1 ) {
		perror("ioctl reads flags");
		close(sock_fd);
		exit(1);
	}
    old_ifr_flags = ethreq.ifr_flags;

	ethreq.ifr_flags |= IFF_PROMISC;
	if( ioctl(sock_fd, SIOCSIFFLAGS, &ethreq) == -1 ) {
		perror("ioctl set promisc");
		close(sock_fd);
		exit(1);
	}

	/* Attach the filter to the socket */
	if( setsockopt(sock_fd, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) == -1)
	{
		perror("setsockopt");
		close(sock_fd);
		exit(1);
	}


#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wmissing-noreturn"
	while( 1 ) {
        /* Set all file descriptors for select() */
        fd_set read_fds;
        FD_ZERO(&read_fds);
        FD_SET(sig_fd, &read_fds);
        FD_SET(sock_fd, &read_fds);
        int max_fd = sock_fd;

        ret_select = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
        if( ret_select == -1 ) {
            perror("select");
            // Restore the interface Old Flags and exit
            ethreq.ifr_flags = old_ifr_flags;
            ioctl(sock_fd, SIOCSIFFLAGS, &ethreq);
            close(sock_fd);
            exit(-1);
        }

        if (FD_ISSET(sig_fd, &read_fds)) {
            // struct signalfd_siginfo si;
            // ssize_t res = read (sig_fd, &si, sizeof(si));

            // Restore the interface Old Flags and exit
            ethreq.ifr_flags = old_ifr_flags;
            ioctl(sock_fd, SIOCSIFFLAGS, &ethreq);
            close(sock_fd);
            exit(0);
        }

        if (FD_ISSET(sock_fd, &read_fds)) {
            ssize_t recv_n;
            recv_n = recvfrom(sock_fd, buffer, BUFF_SIZE, 0, NULL, NULL);
            if( recv_n == -1 ) {
                perror("recvfrom");
                continue;
            }

            char proto_str[10] = "Unknown";
            uint16_t len = recv_n;
            uint16_t shift = 0;

            if( get_ethernet_info(buffer, len, &shift) == -1 )
                continue;

            len -= shift;
            if( get_ip_info(buffer + shift, len, &shift) == -1 )
                continue;

            len -= shift;
            switch (pkt_info.ip_proto){

                case 17:    // UDP proto
                    if( get_udp_info(buffer + shift, len) == -1)
                        continue;

                    strcpy(proto_str, "UDP");
                break;

                case 6:     // TCP proto
                    if( get_tcp_info(buffer + shift, len) == -1)
                        continue;

                    strcpy(proto_str, "TCP");
                break;

                case 1:     // ICMP proto
                    strcpy(proto_str, "ICMP");
                break;

                default:
                    strcpy(proto_str, "Unknown");
            }

            printf("%s [%s:%d] <-- %s --> %s [%s:%d] \n",
                   pkt_info.src_mac, pkt_info.src_ip, pkt_info.src_port,
                   proto_str,
                   pkt_info.dst_mac, pkt_info.dst_ip, pkt_info.dst_port);

            if( pkt_info.cipso_t1.tag_n == 1 )
                printf("   DOI: %d,  Tag: %d,  Sensitivity: %d,  Categories: %s \n",
                       pkt_info.doi, pkt_info.cipso_t1.tag_n,
                       pkt_info.cipso_t1.slevel, pkt_info.cipso_t1.cats);

            if( pkt_info.cipso_t2.tag_n == 2 )
                printf("   DOI: %d,  Tag: %d,  Sensitivity: %d,  Categories: %s \n",
                       pkt_info.doi, pkt_info.cipso_t2.tag_n,
                       pkt_info.cipso_t2.slevel, pkt_info.cipso_t2.cats);

            if( pkt_info.cipso_t5.tag_n == 3 )
                printf("   DOI: %d,  Tag: %d,  Sensitivity: %d,  Categories: %s \n",
                       pkt_info.doi, pkt_info.cipso_t5.tag_n,
                       pkt_info.cipso_t5.slevel, pkt_info.cipso_t5.cats);

        }
	}
#pragma clang diagnostic pop


}


ssize_t  get_ethernet_info(unsigned char *eth_hdr, uint16_t len, uint16_t *shift)
{
    DP printf("\n%s() \n", __func__);
    //DP memdump2hex(eth_hdr, len, 16);

    /* Extract info from Ethernet header  */
    if( ntohs( *(uint16_t*)(eth_hdr + 12) ) != 0x800 )
        return -1;
    DP printf("  ETH Type = %x \n", ntohs( *(uint16_t*)(eth_hdr + 12) ) );

    snprintf(pkt_info.dst_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             *(eth_hdr+0), *(eth_hdr+1), *(eth_hdr+2), *(eth_hdr+3), *(eth_hdr+4), *(eth_hdr+5));
    snprintf(pkt_info.src_mac, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             *(eth_hdr+6), *(eth_hdr+7), *(eth_hdr+8), *(eth_hdr+9), *(eth_hdr+10), *(eth_hdr+11));


    *shift += 14;
    return 1;
}

ssize_t  get_ip_info(unsigned char *ip_hdr, uint16_t len, uint16_t *shift)
{
    DP printf("\n%s() \n", __func__);
    DP memdump2hex(ip_hdr, len, 16);

    snprintf(pkt_info.src_ip, 16, "%d.%d.%d.%d",
             *(ip_hdr+12), *(ip_hdr+13), *(ip_hdr+14), *(ip_hdr+15));
    snprintf(pkt_info.dst_ip, 16, "%d.%d.%d.%d",
             *(ip_hdr+16), *(ip_hdr+17), *(ip_hdr+18), *(ip_hdr+19));


    uint16_t ip_hdr_len = (*ip_hdr & 0xf) * 4;

    uint16_t extra_opts_len = ((*ip_hdr & 0xf) - 5) * 4;
    unsigned char * extra_opts_p = ip_hdr + 20;
    DP printf("  All extra opts: "); DP memdump2hex( (void*) extra_opts_p, extra_opts_len, extra_opts_len);

    unsigned char *cipso_ptr = NULL;
    int x;
    for( x = 0; x < extra_opts_len;)
    {
        if ( *(extra_opts_p + x) == 134 )	// CIPSO option = #134
        {
            cipso_ptr = extra_opts_p + x;
            break;
        }

        x += *(extra_opts_p + x + 1);

    }
    if( cipso_ptr == NULL )
        return -1;

    uint16_t cipso_opt_len = extra_opts_len - x;
    DP printf("  CIPSO opts:     ");  DP memdump2hex( (void*) cipso_ptr, cipso_opt_len, cipso_opt_len);

    
    if( cipso_payload_decode(cipso_ptr, cipso_opt_len) == -1 )
        return -1;

    pkt_info.ip_proto = *(ip_hdr + 9);

    DP printf("*shift = %d   ip_hdr_len = %d \n", *shift, ip_hdr_len);
    *shift += ip_hdr_len;
    return 1;
}


ssize_t  get_udp_info(unsigned char *udp_hdr, uint16_t len)
{
    DP printf("\n%s() \n", __func__);
    DP memdump2hex(udp_hdr, len, 16);

    pkt_info.src_port = ntohs( *(uint16_t*)udp_hdr);
    pkt_info.dst_port = ntohs( *(uint16_t*)(udp_hdr + 2));

    return 1;
}

ssize_t  get_tcp_info(unsigned char *tcp_hdr, uint16_t len)
{
    DP printf("\n%s() \n", __func__);

    return 1;
}



ssize_t cipso_payload_decode(unsigned char *cipso_hdr, uint16_t cipso_len)
{
    DP printf("\n%s() \n", __func__);

    uint8_t	  tag_type;		    // TAG type [1, 2, 5]
    uint8_t   tag_len;		    // TAG lenght
    uint8_t	 *tag_p;		    // Pointer to TAG start address
    uint8_t	  tag_shift = 6;	// Position of current TAG

    pkt_info.cipso_t1.tag_n = 0;
    pkt_info.cipso_t2.tag_n = 0;
    pkt_info.cipso_t5.tag_n = 0;

    strcpy(pkt_info.cipso_t1.cats, "");
    strcpy(pkt_info.cipso_t2.cats, "");
    strcpy(pkt_info.cipso_t5.cats, "");

    pkt_info.doi = ntohl(  *(uint32_t*)(cipso_hdr + 2));

    /*  Find all TAGs and decode its */
    for( int z = 1; z <=10; z++) {
        tag_p = cipso_hdr + tag_shift;

        tag_type  = (uint8_t)*(tag_p + 0);
        tag_len   = (uint8_t)*(tag_p + 1);

        // TAG decode here
        switch( tag_type ) {
            case 1:
            {
                uint8_t x, x2;

                pkt_info.cipso_t1.tag_n = 1;
                pkt_info.cipso_t1.slevel = (uint8_t)*(tag_p + 3);

                for ( x=0; x < tag_len - 4; x++)
                {
                    for ( x2 = 0; x2 <= 7; x2++) {
                        if ( (*(tag_p + 4 + x) & 0x80 >> x2) != 0 )	{ // 0x80 == 1000 0000
                            char tmp_ch[10] = {0};
                            snprintf(tmp_ch, sizeof tmp_ch, "%d,", x2 + x*8);
                            strncat(pkt_info.cipso_t1.cats, tmp_ch, strlen(tmp_ch));
                        }
                    }
                }
                //if( pkt_info.cipso_type_1.categor[ strlen(pkt_info.cipso_type_1.categor) - 1 ] == ',' )
                //    pkt_info.cipso_type_1.categor[ strlen(pkt_info.cipso_type_1.categor) - 1 ] = '\0';
            }
            break;

            case 2:
            {
                uint16_t tmp_d;
                uint8_t x;

                pkt_info.cipso_t2.tag_n = 2;
                pkt_info.cipso_t2.slevel = (uint8_t)*(tag_p + 3);

                for ( x=4; x < tag_len; x += 2)
                {
                    tmp_d = ntohs( *((uint16_t*)(tag_p + x)) );

                    char tmp_ch[10] = {0};
                    snprintf(tmp_ch, sizeof tmp_ch, "%d,", tmp_d);
                    strncat(pkt_info.cipso_t2.cats, tmp_ch, strlen(tmp_ch));
                }
                //if( pkt_info.cipso_type_2.categor[ strlen(pkt_info.cipso_type_2.categor) - 1 ] == ',' )
                //    pkt_info.cipso_type_2.categor[ strlen(pkt_info.cipso_type_2.categor) - 1 ] = '\0';
            }
            break;

            case 5:
            {
                uint16_t tmp_top, tmp_bottom;
                uint8_t x;

                pkt_info.cipso_t5.tag_n = 5;
                pkt_info.cipso_t5.slevel = (uint8_t)*(tag_p + 3);

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
                        strncat(pkt_info.cipso_t5.cats, tmp_ch, strlen(tmp_ch));
                    } else {
                        char tmp_ch[10] = {0};	// 63000 == 6 chars MAX
                        snprintf(tmp_ch, sizeof tmp_ch, "%d,", tmp_top);
                        strncat(pkt_info.cipso_t5.cats, tmp_ch, strlen(tmp_ch));
                    }
                }
                //if( pkt_info.cipso_type_5.categor[ strlen(pkt_info.cipso_type_5.categor) - 1 ] == ',' )
                //    pkt_info.cipso_type_5.categor[ strlen(pkt_info.cipso_type_5.categor) - 1 ] = '\0';
            }
            break;

            default:
                printf("   Unknown TAG type = %d \n", tag_type);
                return 1;
        }


        tag_shift += tag_len;
        if(  tag_shift >= cipso_len )
            break;
    }

    return 1;
}


// Convert memory dump to hex
void memdump2hex( void* dump, uint16_t len, uint8_t columm) {
    uint16_t x;
    unsigned char *ch = (unsigned char*) dump;

    printf("  ");
    for(x=0; x < len; x++) {
        if( x>0 && x%columm == 0)
            printf("\n  ");
        printf("%02x ", *(ch + x));
    }
    printf("\n");
}

