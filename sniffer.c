#include <pcap.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define MAX_LINE                    2048
#define TCP_CONNECTION_TABLE_SIZE   4096

//Structs
typedef struct node {
    char *data;
    struct node *next;
} Node;

typedef struct tcp_connection {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t start_ts_ms;
    uint64_t last_ts_ms;
    uint32_t pkt_in;
    uint32_t pkt_out;
    uint8_t fin_count;
    uint8_t closed;
    struct tcp_connection *next;
} tcp_connection_t;

pthread_mutex_t lock    = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  cond    = PTHREAD_COND_INITIALIZER;
Node *queue_head        = NULL;
Node *queue_tail        = NULL;
int done                = 0;
tcp_connection_t *tcp_conn_table[TCP_CONNECTION_TABLE_SIZE];


//Enqueue & Dequeue (Producer-Consumer Algo)
void enqueue(char *s) 
{
    Node *n = malloc(sizeof(Node));
    if(n == NULL)
	{
		return;
	}
	
    n->data = s;
    n->next = NULL;
    pthread_mutex_lock(&lock);
    
    int was_empty = (queue_tail == NULL);
	
	if(was_empty)
	{
		//queue is empty
		queue_head = n;
		queue_tail = n;
	}
	else
	{
		queue_tail->next = n;
		queue_tail = n;
	}
	
	if (was_empty)
	{
		pthread_cond_signal(&cond);
	}
	pthread_mutex_unlock(&lock);
}

Node *dequeue(void)
{
	Node *n = NULL;
	
    pthread_mutex_lock(&lock);
    
    while(queue_head == NULL && !done)
	{
		pthread_cond_wait(&cond, &lock);
	}
	
	if  (queue_head != NULL)
	{
		n = queue_head;
		queue_head = queue_head->next;
		
		if(queue_head == NULL)
		{
			queue_tail = NULL;
		}	
	}
	
	pthread_mutex_unlock(&lock);
    return n;
}

//Logger Thread
void *logging_thread(void *arg)
{
    FILE *fileptr = (FILE *)arg;

    while (1) {
        Node *n = dequeue();
        if (n == NULL)
		{
            break;
		}
		else
		{
			fprintf(fileptr, "%s\n", n->data);
		}
        //fflush(fileptr); /*It can be enabled later for high PPS scenario*/
        free(n->data);
        free(n);
    }
    return NULL;
}

//HashTable helper fucntions Starts here
static inline uint32_t tcp_conn_hash(uint32_t s, uint32_t d,
                                 uint16_t sp, uint16_t dp)
{
    return (s ^ d ^ sp ^ dp) & (TCP_CONNECTION_TABLE_SIZE - 1);
}

static inline uint64_t current_time_ms(const struct pcap_pkthdr *h)
{
    return (uint64_t)h->ts.tv_sec * 1000 +
           (uint64_t)h->ts.tv_usec / 1000;
}

tcp_connection_t *get_tcp_conn(struct ip *ip,
                     struct tcphdr *tcp,
                     const struct pcap_pkthdr *h)
{
    uint32_t s = ip->ip_src.s_addr;
    uint32_t d = ip->ip_dst.s_addr;
    uint16_t sp = tcp->th_sport;
    uint16_t dp = tcp->th_dport;

    /* canonical direction */
    if (s > d || (s == d && sp > dp)) 
    {
        uint32_t tmp_ip = s; s = d; d = tmp_ip;
        uint16_t tmp_p  = sp; sp = dp; dp = tmp_p;
    }

    uint32_t idx = tcp_conn_hash(s, d, sp, dp);
    tcp_connection_t *f = tcp_conn_table[idx];

    while(f)
    {
        if(f->src_ip == s && f->dst_ip == d &&
        f->src_port == sp && f->dst_port == dp)
        {
            return f;
        }
        f = f->next;
    }

    // New Connection
    f = calloc(1, sizeof(*f));
    f->src_ip = s;
    f->dst_ip = d;
    f->src_port = sp;
    f->dst_port = dp;
    f->start_ts_ms = current_time_ms(h);
    f->last_ts_ms  = f->start_ts_ms;

    f->next = tcp_conn_table[idx];
    tcp_conn_table[idx] = f;
    return f;
}
//HashTable helper functions Ends here

//pcap capture callback function - packet capture logic
void pcap_callback_func(u_char *args,
                    const struct pcap_pkthdr *pcap_pkt_header,
                    const u_char *packet)
{
    (void)args; //unused variable

    struct ether_header *ethernet_header    = NULL;
    struct ip *ip_packet                    = NULL;
    struct tcphdr *tcp_packet               = NULL;
    struct udphdr *udp_packet               = NULL;
    char *tcp_payload                       = NULL;
    char *hostname                          = NULL;
    char *useragent                         = NULL;
    int ip_headerlen                        = 0;
    int tcp_headerlen                       = 0;
    int tcp_payload_len                     = 0;
    char host_buf[256]                      = "-";;
    char ua_buf[512]                        = "-";;
    tcp_connection_t *tcp_conn              = NULL;
    uint64_t duration                       = 0;
    char src_mac_addr[18];
    char dst_mac_addr[18];
    char src_ip_addr[16];
    char dst_ip_addr[16];
    char line[MAX_LINE];

    ethernet_header = (struct ether_header *)packet;
    if (ntohs(ethernet_header->ether_type) != ETHERTYPE_IP)
    {
        return;
    }

    snprintf(src_mac_addr, sizeof(src_mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethernet_header->ether_shost[0], ethernet_header->ether_shost[1],
             ethernet_header->ether_shost[2], ethernet_header->ether_shost[3],
             ethernet_header->ether_shost[4], ethernet_header->ether_shost[5]);

    snprintf(dst_mac_addr, sizeof(dst_mac_addr), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethernet_header->ether_dhost[0], ethernet_header->ether_dhost[1],
             ethernet_header->ether_dhost[2], ethernet_header->ether_dhost[3],
             ethernet_header->ether_dhost[4], ethernet_header->ether_dhost[5]);

    ip_packet = (struct ip *)(packet + sizeof(struct ether_header));
    ip_headerlen = ip_packet->ip_hl * 4;

    inet_ntop(AF_INET, &ip_packet->ip_src, src_ip_addr, sizeof(src_ip_addr));
    inet_ntop(AF_INET, &ip_packet->ip_dst, dst_ip_addr, sizeof(dst_ip_addr));

    //TCP Packet parsing
    if (ip_packet->ip_p == IPPROTO_TCP) 
    {
        tcp_packet = (struct tcphdr *)((u_char *)ip_packet + ip_headerlen);
        tcp_headerlen = tcp_packet->th_off * 4;
        tcp_payload = (char *)tcp_packet + tcp_headerlen;
        tcp_payload_len = ntohs(ip_packet->ip_len) - ip_headerlen - tcp_headerlen;

        snprintf(line, sizeof(line),
            "MAC %s -> %s | IP %s:%d -> %s:%d | TCP",
            src_mac_addr, dst_mac_addr,
            src_ip_addr, ntohs(tcp_packet->th_sport),
            dst_ip_addr, ntohs(tcp_packet->th_dport));
        enqueue(strdup(line));

        //TCP Connection Tracking Logic
        tcp_conn = get_tcp_conn(ip_packet, tcp_packet, pcap_pkt_header);
        tcp_conn->last_ts_ms = current_time_ms(pcap_pkt_header);

        /* OUT PKT , src → dst when seen first*/
        if (ip_packet->ip_src.s_addr == tcp_conn->src_ip &&
            tcp_packet->th_sport == tcp_conn->src_port)
        {
            tcp_conn->pkt_out++;
        }
        else
        {
            tcp_conn->pkt_in++;
        }

        /* RST PKT , when immediate close */
        if (tcp_packet->th_flags & TH_RST)
        {
            tcp_conn->fin_count = 2;
        }

        /* FIN PKT , half close connection*/
        if (tcp_packet->th_flags & TH_FIN)
        {
            tcp_conn->fin_count++;
        }

        /* Close connection only when fully closed */
        if (tcp_conn->fin_count >= 2 && !tcp_conn->closed)
        {
            tcp_conn->closed = 1;
            duration = tcp_conn->last_ts_ms - tcp_conn->start_ts_ms;

            char tcp_conn_summary[256];
            char s_ip[16], d_ip[16];

            inet_ntop(AF_INET, &tcp_conn->src_ip, s_ip, sizeof(s_ip));
            inet_ntop(AF_INET, &tcp_conn->dst_ip, d_ip, sizeof(d_ip));

            snprintf(tcp_conn_summary, sizeof(tcp_conn_summary),
                "TCP END %s:%d -> %s:%d | IN=%u OUT=%u | DURATION=%lums",
                s_ip,
                ntohs(tcp_conn->src_port),
                d_ip,
                ntohs(tcp_conn->dst_port),
                tcp_conn->pkt_in,
                tcp_conn->pkt_out,
                duration);

            enqueue(strdup(tcp_conn_summary));

            /* removing tcp_conn from hash table entry*/
            uint32_t idx = tcp_conn_hash(tcp_conn->src_ip, tcp_conn->dst_ip,
                                    tcp_conn->src_port, tcp_conn->dst_port);

            tcp_connection_t **pp = &tcp_conn_table[idx];
            while (*pp && *pp != tcp_conn)
            {
                pp = &(*pp)->next;
            }
            if (*pp)
            {
                *pp = tcp_conn->next;
            }
            free(tcp_conn);
        }

        if (tcp_payload_len <= 0)
        {
            return;
        }

        //HTTP Parsing Logic
        if (!strncmp(tcp_payload, "GET ", 4) ||
            !strncmp(tcp_payload, "POST ", 5))
        {
            hostname = strstr(tcp_payload, "Host:");
            if (hostname) {
                sscanf(hostname, "Host: %255[^\r\n]", host_buf);
            }

            useragent = strstr(tcp_payload, "User-Agent:");
            if (useragent) {
                sscanf(useragent, "User-Agent: %511[^\r\n]", ua_buf);
            }

            snprintf(line, sizeof(line),
                "MAC %s -> %s | IP %s:%d -> %s:%d | HTTP | HOST=%s | UA=%s",
                src_mac_addr, dst_mac_addr,
                src_ip_addr, ntohs(tcp_packet->th_sport),
                dst_ip_addr, ntohs(tcp_packet->th_dport),
                host_buf, ua_buf);

            enqueue(strdup(line));
        }
    }
    //UDP PAcket parsing
    else if (ip_packet->ip_p == IPPROTO_UDP) 
    {
        udp_packet = (struct udphdr *)((u_char *)ip_packet + ip_headerlen);
        
        snprintf(line, sizeof(line),
            "MAC %s -> %s | IP %s:%d -> %s:%d | UDP",
            src_mac_addr, dst_mac_addr,
            src_ip_addr, ntohs(udp_packet->uh_sport),
            dst_ip_addr, ntohs(udp_packet->uh_dport));
        
        enqueue(strdup(line));
    }
}

//Main Function
int main(int argc, char *argv[])
{
    char *interface     = NULL;
    char *pcapfile      = NULL;
    char *outputfile    = NULL;
    FILE *fileptr       = NULL;
    int opt             = 0;
    char errbuf[256];
    

    while((opt = getopt(argc, argv, "i:r:o:")) != -1) 
    {
        switch(opt)
        {
            case 'i': 
                interface = optarg; 
                break;
            case 'r': 
                pcapfile = optarg; 
                break;
            case 'o': 
                outputfile = optarg; 
                break;
        }
    }

    if ((interface == NULL && pcapfile == NULL) || (outputfile == NULL)) 
    {
        fprintf(stderr,
                "Usage: %s (-i <interface_name> or -r <pcap_file_name>) -o <output_file_name>\n", argv[0]);
        exit(1);
    }

    fileptr = fopen(outputfile, "w");
    if (fileptr == NULL) 
    {
        perror("Error in opening File");
        exit(1);
    }

    //Starting logging thread
    pthread_t logger;
    pthread_create(&logger, NULL, logging_thread, fileptr);

    pcap_t *handle = NULL;
    if (interface) 
    {
        handle = pcap_open_live(interface, 65535, 1, 1000, errbuf);
    } 
    else 
    {
        handle = pcap_open_offline(pcapfile, errbuf);
    }

    if (handle == NULL) {
        fprintf(stderr, "Error in pcap: %s\n", errbuf);
        exit(1);
    }

    //Starting packet capture in main thread
    pcap_loop(handle, 0, pcap_callback_func, NULL);

    pthread_mutex_lock(&lock);
    done = 1;
    pthread_cond_signal(&cond);
    pthread_mutex_unlock(&lock);

    pthread_join(logger, NULL);

    //cleaning up tcp_conn objects at the time of exit, Noted in Valgrind.
    for (int i = 0; i < TCP_CONNECTION_TABLE_SIZE; i++)
    {
        tcp_connection_t *tcp_conn = tcp_conn_table[i];
        while (tcp_conn) 
        {
            tcp_connection_t *next = tcp_conn->next;
            free(tcp_conn);
            tcp_conn = next;
        }
    }
    
    pcap_close(handle);
    fclose(fileptr);

    return 0;
}
