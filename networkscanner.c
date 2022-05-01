/*
    Author: Friedrich Gross
    Personal implementation of a TCP Syn-Flood scanner.
    Issues: Doesnt display responses, either due to Error in the receiving socket or because the Process terminates too fast.

    I created this as a task in college (in an effort to learn about portscanning).
*/


#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <libnet.h>
#include <stdio.h>
#include <errno.h>
#include <error.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>

// !!! compile via: gcc -Wall -pthread networkScanner.c -lnet

struct ipv4_addresses
{
    int target_addr;
    int source_addr;
};

void printHelp()
{
    printf("[!!] USAGE:\ntps <target ip> <source IP>\n");
}

void fail(int errsv, char errString[])
{
    printf("[-] Error: %s failed with errno at %d\n", errString, errsv);
    exit(errsv);
}

void scan(int range_start, int range_end, void* addresses)
{
    struct ipv4_addresses* addrs = (struct ipv4_addresses*)addresses;
    
    libnet_ptag_t protocol_tag;
    libnet_t* libnet_context;
    char err_Buf[LIBNET_ERRBUF_SIZE];
    unsigned char *packet_buffer;

    int i = range_start, sockfd = 0, recvd_bytes = 0;
    struct sockaddr_in receiving_socket;
    struct timeval timeout;

    timeout.tv_sec = 0;
    timeout.tv_usec = 150000;

        //start libnet environment to send packets, REMEMBER TO RUN AS SUDO
    if((libnet_context = libnet_init(LIBNET_RAW4, "wlp3s0", err_Buf)) == NULL)
    {
        fail(errno, "libnet init");
    }
    
    while(i <= range_end ) 
    {
        // CREATING PACKET        
        protocol_tag = libnet_build_tcp(  // builds header, returns protocol tag value
            i,                            // source port
            i,                            // dest port
            1,                            // seq number
            0,                            // ack number
            0x02,                         // flags (0x02 == syn)
            512,                          // window size in bytes
            0,                            // checksum (0 for libnet to autofill)
            0,                            // urgent pointer
            LIBNET_TCP_H,                 // length of tcp packet(this macro == 0x14 == 20, ergo on bytes)
            0,                            // payload (dont have one)
            0,                            // payload length
            libnet_context,               // libnet context to give this packet to
            0);                           // protocol tag to edit existing TCP hdr, 0 for new
        if (protocol_tag < 0)
        {
            libnet_destroy(libnet_context);
            fail(errno, "tcp crafting");
        }
        
        protocol_tag = libnet_build_ipv4(   // build ip part of packet
            LIBNET_IPV4_H + LIBNET_TCP_H,   // length of entire packet, 0x14 + 0x14
            IPTOS_LOWDELAY,                 // type of service, 0x10 for low delay
            i,                              // id of packet
            0,                              // fragmentation
            64,                             // ttl
            0x06,                           // upper layer protocol number taken from IANA List
            0,                              // checksum, 0 to let libnet do it
            addrs->source_addr,             // source ip
            addrs->target_addr,             // target addr
            NULL,                           // payload
            0,                              // payload length
            libnet_context,                 // libnet context to give packet to
            0);                             // protocol tag
        if (protocol_tag < 0)
        {
            libnet_destroy(libnet_context);
            fail(errno, "ip crafting");
        }

        
        // PREPARE RECEIVING SOCKET

        memset(&receiving_socket, '\0', sizeof(receiving_socket));
        receiving_socket.sin_family = AF_INET;
        receiving_socket.sin_port = htons(i);
        receiving_socket.sin_addr.s_addr = addrs->source_addr;
        
        if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        { 
            fail(errno, "socket instancing");
        }

        if((packet_buffer = (unsigned char*)malloc(65536)) == NULL)
        {
            fail(errno, "packet memory alloc");
        }
        
        if(bind(sockfd, (struct sockaddr*)&receiving_socket, sizeof(receiving_socket))!= 0 )
        {
            fail(errno, "binding socket");
        }
        
        if(setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout)) < 0)
        {
            fail(errno, "socket timeout set");
        }
        
        // SENDING AND RECEIVING

        if(libnet_write(libnet_context) < 0)
        { 
            fail(errno, "libnet send");
        }

        recvd_bytes = recvfrom(sockfd, packet_buffer, 65536, 0, (struct sockaddr*)&receiving_socket, (socklen_t*)sizeof(receiving_socket));
        
        /* commented, da man immer errno 11 bekommt nach timeout von recvfrom, was hier zu erwarten ist
        if(recvd_bytes < 0) {
            fail(errno, "receiving packets");}
        */

        if(recvd_bytes > 0) 
        {
            printf("Received answer from Port %d", i);
        }

        libnet_clear_packet(libnet_context);
        close(sockfd);
        free(packet_buffer);
        i++;
    }
    libnet_destroy(libnet_context);
}

void* thread2(void* addresses)
{
    scan(8192, 16384, addresses);
    pthread_exit(NULL);
    return(NULL);
}

void* thread3(void* addresses)
{
    scan(16385, 24576, addresses);
    pthread_exit(NULL);
    return(NULL);
}

void* thread4(void* addresses)
{
    scan(24577, 32768, addresses);
    pthread_exit(NULL);
    return(NULL);
}

void* thread5(void* addresses)
{
    scan(32769, 40960, addresses);
    pthread_exit(NULL);
    return(NULL);
}

void* thread6(void* addresses)
{   
    scan(40961, 49151, addresses);
    pthread_exit(NULL);
    return(NULL);
}


int main(int argc, char *argv[])
{   
    if(argc < 3) 
    {
        printHelp();
        exit(1);
    }

    pthread_t t2_handler, t3_handler, t4_handler, t5_handler, t6_handler;
    struct ipv4_addresses addresses;
    
    addresses.target_addr = inet_addr(argv[1]);
    addresses.source_addr = inet_addr(argv[2]);

    if(pthread_create(&t2_handler, NULL, thread2, (void*)&addresses) != 0)
    {
        fail(errno, "thread 2 creation");
    }
    if(pthread_create(&t3_handler, NULL, thread3, (void*)&addresses) != 0)
    {
        fail(errno, "thread 3 creation");
    }
    if(pthread_create(&t4_handler, NULL, thread4, (void*)&addresses) != 0)
    {
        fail(errno, "thread 4 creation");
    }
    if(pthread_create(&t5_handler, NULL, thread5, (void*)&addresses) != 0)
    {
        fail(errno, "thread 5 creation");
    }
    if(pthread_create(&t6_handler, NULL, thread6, (void*)&addresses) != 0)
    {
        fail(errno, "thread 6 creation");
    }
    scan(1024, 8191, &addresses);

    pthread_join(t2_handler, NULL);
    pthread_join(t3_handler, NULL);
    pthread_join(t4_handler, NULL);
    pthread_join(t5_handler, NULL);
    pthread_join(t6_handler, NULL);
    printf("[+] All Threads exited successfully.\n");
    
    return 0;
}