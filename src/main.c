// $Id: dhcp_sniff.c,v 1.2 2017/04/21 13:45:27 hito Exp hito $

#include <assert.h>
#include <libgen.h>
#include <time.h>
#include <signal.h>
#include <string.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

// pcap
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

// mosquitto
#include <mosquitto.h>

#include "logger.h"

// globals
const char* g_program = NULL;
int g_verbose = 0;

// pcap
const char *g_net_addr = NULL;

// mqtt
struct mosquitto* g_mosq = NULL;
const char* g_mqtt_topic = NULL;
enum message_fmt {FMT_BINARY=0, FMT_JSON} g_message_fmt = FMT_JSON;

// pcap loop
static void loop (u_char*, const struct pcap_pkthdr*, const u_char*);
//static void on_connect (struct mosquitto*, void*, int);
static inline void big_to_little (u_char* src, u_char* tgt, int n);

// signal handler
static void quit (int sig);

//
int
main (int argc, char **argv)
{
    g_program = basename (argv[0]);
    const char* dev = NULL;
    //char* dev = "eth0";
    const char* filter_exp = "port 67";

    // mosquitto
    char* mqtt_host = getenv ("MQTT_SERVER");
    mqtt_host = mqtt_host ? mqtt_host : "localhost";
    int mqtt_port = 1883;
    g_mqtt_topic = getenv ("MQTT_TOPIC");
    if (!g_mqtt_topic) g_mqtt_topic = "dhcp_watch";

    int i;
    for (i = 1; i < argc; i++)
    {
        if (!strcmp (argv[i], "-i"))
            dev = argv[++i];
        else if (!strcmp (argv[i], "-f"))
            filter_exp = argv[++i];

        else if (!strcmp (argv[i], "-b"))
            mqtt_host = argv[++i];
        else if (!strcmp (argv[i], "-t"))
            g_mqtt_topic = argv[++i];


        // deprecated
        else if (!strncmp (argv[i], "--format=", 9))
	{
	    const char* fmt = argv[i] + 9;
            if (!strncmp (fmt, "bin", 3))
		g_message_fmt = FMT_BINARY;
            else
		g_message_fmt = FMT_JSON;
	}

        else if (!strcmp (argv[i], "-q"))
            g_verbose = 0;
        else if (!strcmp (argv[i], "-v"))
            g_verbose = 1;
        //else if (!strcmp (argv[i], "-vv"))
        //    g_verbose = 2;
        else if (!strcmp (argv[i], "-h"))
        {
            printf ("%s -- detects and reports each broadcast packet to port 67 (BOOTP/DHCPREQUEST)\n",
                    g_program);
            printf ("usage: %s [-i <iface>] [-f <filter>] [-b <broker>]\n",
                    g_program);
            return (0);
        }
        else
        {
            fprintf (stderr, "invalid argument: \"%s\"\n", argv[i]);
            exit (-1);
        }
    }

    // dev
    char errbuf[PCAP_ERRBUF_SIZE];
    if (!dev) dev = pcap_lookupdev (errbuf);
    assert (dev);

    // net
    bpf_u_int32 net;	// ip of the sniffing device
    bpf_u_int32 mask;
    int rc = 0;
    rc = pcap_lookupnet (dev, &net, &mask, errbuf);
    assert (rc == 0);

    //struct in_addr net_addr;
    struct in_addr net_addr;
    net_addr.s_addr = net;
    g_net_addr = inet_ntoa (net_addr);

    syslog (LOG_NOTICE, "dev=%s net=%s(oct:%08x)", dev, g_net_addr, net);
    if (0)
    {
        fprintf (stderr, ";; %s [init] dev=%s ", g_program, dev);
        fprintf (stderr, "net=%s(oct:%08x) ", g_net_addr, net);
        struct in_addr addr;
        addr.s_addr = mask;
        char* mask_str = inet_ntoa (addr);
        fprintf (stderr, "mask=%s(hex:%08x)\n", mask_str, mask);
    }

    // handle
    pcap_t* handle = pcap_open_live (dev, BUFSIZ, 0, 1000, errbuf);
      // dev, snaplen, promiscuous, to_ms, ebuf
    if (!handle)
    {
        fprintf (stderr, "** pcap_open_live failed. permission problem?\n");
        exit (1);
    }
    assert (handle);

    // filter
    struct bpf_program fp;		// filter program (compiled)
    //char filter_exp[] = "dst host 192.168.10.5 and dst port 22";
    assert (filter_exp);
    rc = pcap_compile (handle, &fp, filter_exp, 0, net);
    assert (rc == 0);

    rc = pcap_setfilter (handle, &fp);
    assert (rc == 0);

    if (g_verbose > 1)
    {
        fprintf (stderr, ";; %s [init] filter=\"%s\"\n", g_program, filter_exp);
    }

    // mqtt
    char* mqtt_ptr = strchr (mqtt_host, ':');
    if (mqtt_ptr)
    {
        *mqtt_ptr = '\0';
        mqtt_port = atoi (mqtt_ptr + 1);
    }

    // signal traps
    signal (SIGTERM, quit);
    signal (SIGHUP, quit);
    signal (SIGINT, quit);

#if 1
    // daemonization
    pid_t child_pid = fork ();
    if (child_pid < 0) { fprintf (stderr, "fork failed\n"); exit (1); }
    if (child_pid > 0) { fprintf (stderr, "forked: %d\n", child_pid); exit (0); }
    umask (0);
    pid_t sid = setsid ();  // run the process in a new session
    if (sid < 0) exit(1);
    chdir ("/");
    close (STDIN_FILENO);
    close (STDOUT_FILENO);
    close (STDERR_FILENO);
#endif

    // mosquitto
    // ** note: this must be done after daemonization
    struct mosquitto* mosq = NULL;
    mosquitto_lib_init ();
    mosq = mosquitto_new (NULL, true, NULL);
    assert (mosq);
    g_mosq = mosq;
    assert (mqtt_host);
    //mosquitto_connect_callback_set (mosq, NULL);
    const int keep_alive = 60;
      // note: connection will be lost if no message is transmitted for (1.5 * keep_alive) seconds
    int rslt = mosquitto_connect_bind (mosq, mqtt_host, mqtt_port, keep_alive, NULL);
      // mosq, host, port, keep_alive, bind_addr
    if (rslt != MOSQ_ERR_SUCCESS)
    {
        syslog (LOG_ERR, "mosquitto_connect_bind failed (0x%02x, broker=%s)", rslt, mqtt_host);
        exit (1);
    }
    assert (rslt == MOSQ_ERR_SUCCESS);
    rslt = mosquitto_loop_start (mosq);	// threaded
    assert (rslt == MOSQ_ERR_SUCCESS);

    // pcap loop
    openlog (g_program, LOG_PID, LOG_USER);
    syslog (LOG_NOTICE, "starts pcap_loop for %s", dev);
    rc = pcap_loop (handle, -1, loop, (u_char*) mosq);
    assert (rc == -1);
    //fprintf (stderr, ";; %s **ERROR: %s", g_program, pcap_geterr (handle));

    pcap_freecode (&fp);
    pcap_close (handle);

    raise (SIGTERM);
    return (0);
}

//
static void
loop (u_char* user, const struct pcap_pkthdr* header, const u_char* packet)
{
    //struct pcap_pkthdr* header = NULL;
    //const u_char* packet = NULL;
    //rc = pcap_next_ex (handle, &header, &packet);
    //if (rc == -1) exit (-1);
    //if (rc != 1) { sleep (3); continue; }

    assert (header && packet);
    {
        const struct timeval* tv = &header->ts;
        struct tm* tm = localtime (&tv->tv_sec);
        syslog (LOG_INFO, "pcap loop [%d-%02d-%02dT%02d:%02d:%02d] caplen=%d len=%d",
                tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
                tm->tm_hour, tm->tm_min, tm->tm_sec,
                header->caplen, header->len);
    }

    // L2: ethernet -- header:14bytes
    const int ETHER_ADDR_LEN = 6;
    const int SIZE_ETHERNET = 14;
    struct sniff_ethernet
    {
        u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
        u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
        u_short ether_type; /* IP? ARP? RARP? etc */
    };
    void* ptr = (void*) packet;
    const struct sniff_ethernet* ethernet = (struct sniff_ethernet*) ptr;
    assert (ethernet);
    assert (sizeof (struct sniff_ethernet) == SIZE_ETHERNET);
    ptr += SIZE_ETHERNET;

    u_short ether_type;
    big_to_little (&ethernet->ether_type, &ether_type, 2);
    assert (ether_type == 0x0800);	// IPv4

    if (0)
    {
        fprintf (stderr, ";; %s [eth]", g_program);

        fprintf (stderr, " src=");
        int i;
        for (i = 0; i < 6; i++)
            fprintf (stderr, "%02x", ethernet->ether_shost[i]);

        fprintf (stderr, " dst=");
        //for (int i = 0; i < 6; i++)
        //    fprintf (stderr, "%02x", ethernet->ether_dhost[i]);
        uint64_t addr = 0;
        for (i = 0; i < 6; i++)
            addr = addr * 0x100 + ethernet->ether_dhost[i];
        fprintf (stderr, "%012lx", addr);

        fprintf (stderr, " type=%04x\n", ether_type);
    }

    // L3: ip (v4) -- header:20bytes
    struct sniff_ip
    {
        u_char ip_vhl;		/* version << 4 | header length >> 2 */
        u_char ip_tos;		/* type of service */
        u_short ip_len;		/* total length */
        u_short ip_id;		/* identification */
        u_short ip_off;		/* fragment offset field */
        u_char ip_ttl;		/* time to live */
        u_char ip_p;		/* protocol */
        u_short ip_sum;		/* checksum */
        struct in_addr ip_src, ip_dst; /* source and dest address */
    };
    const struct sniff_ip* ip = (struct sniff_ip*) ptr;
    assert (ip);
    assert (ip->ip_vhl & (4 << 4));		// ipv4
    //u_int size_ip = IP_HL (ip) * 4;
    u_int size_ip = (ip->ip_vhl & 0x0f) * 4;	// header length
    assert (size_ip == sizeof (struct sniff_ip));
    assert (size_ip >= 20);
    ptr += size_ip;

    u_short ip_len;
    big_to_little (&ip->ip_len, &ip_len, 2);

    if (0)
    {
        fprintf (stderr, ";; %s [ip] ", g_program);
        fprintf (stderr, "src=%08x=%s ",
                 ip->ip_src.s_addr, inet_ntoa (ip->ip_src));
        fprintf (stderr, "dst=%08x=%s ",
                 ip->ip_dst.s_addr, inet_ntoa (ip->ip_dst));
        fprintf (stderr, "len=%u ", ip_len);
        fprintf (stderr, "proto=%u ", ip->ip_p);
        fprintf (stderr, "\n");
    }

    // L4: tcp/udp -- header:8bytes
    //const struct sniff_tcp* tcp = NULL;
    //u_int size_tcp = TH_OFF(tcp)*4;
    //if (ip->ip_p != IPPROTO_UDP) return;
    assert (ip->ip_p == IPPROTO_UDP);
    struct sniff_udp
    {
        u_short uh_sport;               /* source port */
        u_short uh_dport;               /* destination port */
        u_short uh_ulen;                /* udp length */
        u_short uh_sum;                 /* udp checksum */
    };
    const struct sniff_udp* udp = (struct sniff_udp*) ptr;
    assert (udp);
    u_int size_udp = ntohs (udp->uh_ulen);
    assert (size_udp >= 20);
    ptr += sizeof (struct sniff_udp);

    u_short uh_sport, uh_dport;
    big_to_little (&udp->uh_sport, &uh_sport, 2);
    big_to_little (&udp->uh_dport, &uh_dport, 2);

    if (0)
    {
        fprintf (stderr, ";; %s [udp] src=%d dst=%d\n",
                 g_program, uh_sport, uh_dport);
    }

    // dhcp
    // cf. https://www.isc.org/downloads/file/dhcp-4-3-5/?version=tar-gz
    struct sniff_dhcp
    {
  	u_int8_t  op;		/* 0: Message opcode/type */
	u_int8_t  htype;	/* 1: Hardware addr type (net/if_types.h) */
	u_int8_t  hlen;		/* 2: Hardware addr length */
	u_int8_t  hops;		/* 3: Number of relay agent hops from client */
	u_int32_t xid;		/* 4: Transaction ID */
	u_int16_t secs;		/* 8: Seconds since client started looking */
	u_int16_t flags;	/* 10: Flag bits */
	struct in_addr ciaddr;	/* 12: Client IP address (if already in use) */
	struct in_addr yiaddr;	/* 16: Client IP address */
	struct in_addr siaddr;	/* 18: IP address of next server to talk to */
	struct in_addr giaddr;	/* 20: DHCP relay agent IP address */
	u_char chaddr [16];	/* 24: Client hardware address */
	char sname [64];	/* 40: Server name */
	char file [128];	/* 104: Boot filename */
	u_char options [1];	/* 212: Optional parameters */
    };
    const struct sniff_dhcp* dhcp = (struct sniff_dhcp*) ptr;
    const int op = (dhcp->op & 0x0f);	// bootrequest or bootreply
    int msg_t = 3;
    if (dhcp->options[4] == 0x35)
        msg_t = dhcp->options[6];
    else
        // guess...
    {
        if (op == 1)
            // bootrequest: client -> server
        {
            assert (ip->ip_src.s_addr == 0);
            assert (ip->ip_dst.s_addr == 0xffffffff);
            assert (uh_sport == 68 && uh_dport == 67);
            //if (dhcp->ciaddr.s_addr == 0 && dhcp->yiaddr.s_addr == 0)
            if (0)
                // discovery
                msg_t = 1;
            else
                // request
                msg_t = 3;

        }
        else if (op == 2)
            // bootreply: server -> client
        {
            assert (uh_sport == 67 && uh_dport == 68);
            if (ip->ip_dst.s_addr == 0xffffffff)
                // offer
            {
                assert (dhcp->ciaddr.s_addr != 0 || dhcp->yiaddr.s_addr != 0);
                msg_t = 2;
            }
            else
                // ack/nack
            {
                assert (ip->ip_dst.s_addr == dhcp->yiaddr.s_addr);
                msg_t = 5;
            }
        }
        else
            assert (0);
    }

    if (0)
    {
        fprintf (stderr, ";; %s [dhcp] %s message_type=%d ciaddr=%s yiaddr=%s\n",
                 g_program,
                 (op == 1) ? "BOOTREQUEST" : "BOOTREPLY" , msg_t,
                 inet_ntoa (dhcp->ciaddr), inet_ntoa (dhcp->yiaddr));
    }

    if (msg_t != 3) return;

    // publish (when DHCPREQUEST is emitted)
    assert (user);
    struct mosquitto* mosq = (struct mosquitto*) user;
    while (1)
    {
        // publish mac address
	//int rslt = mosquitto_publish (mosq, NULL, g_mqtt_topic, 6, ethernet->ether_shost, 0, false);
	int rslt = MOSQ_ERR_SUCCESS;
	switch (g_message_fmt)
	{
	case FMT_BINARY:
	    rslt = mosquitto_publish (mosq, NULL, g_mqtt_topic, 6, ethernet->ether_shost, 0, false);
	    break;
	default:
            {
                char payload[100];
                u_char* mac = ethernet->ether_shost;
                snprintf (payload, 100,
                          "{\"mac_address\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"network_address\":\"%s\"}",
                          mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
                          g_net_addr);
                rslt = mosquitto_publish (mosq, NULL, g_mqtt_topic, strlen (payload) + 1, payload, 0, false);
            }
	}
        if (rslt == MOSQ_ERR_SUCCESS) break;

        switch (rslt)
        {
        case MOSQ_ERR_CONN_LOST:
            sleep (3);
            mosquitto_reconnect (mosq);
            break;
        default:
            sleep (10);
            syslog (LOG_ERR, "mosquitto_publish failed: (%d) %s", rslt, mosquitto_strerror (rslt));
            raise (SIGTERM);
        }
    }

    u_char* mac = ethernet->ether_shost;
    syslog (LOG_NOTICE, "mosquitto_publish (%s): %02x:%02x:%02x:%02x:%02x:%02x",
                        g_mqtt_topic,
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static inline void
big_to_little (u_char* src, u_char* tgt, int n)
{
    int i;
    for (i = 0; i < n; i++) tgt[i] = src[n - (i + 1)];
}

static void
quit (int sig)
{
    //std::cerr << "quit: SIGNAL=" << sig << "\n";
    fprintf (stderr, "SIGNAL = %d\n", sig);

    // mosquitto
    if (!g_mosq) exit (0);
    mosquitto_disconnect (g_mosq);
    mosquitto_destroy (g_mosq);
    mosquitto_lib_cleanup ();
    g_mosq = NULL;

    // syslog
    syslog (LOG_NOTICE, "quit (signal = %d)", sig);
    closelog ();

    exit (0);
}

// wrapper of the common syslog function
void
_syslog (int prio, const char* fmt, ...)
{
    if (g_verbose == 0 && prio >= LOG_NOTICE) return;
    if (g_verbose == 1 && prio >= LOG_INFO) return;
    if (g_verbose == 2 && prio >= LOG_DEBUG) return;
        
    va_list ap;
    va_start (ap, fmt);
    vsyslog (prio, fmt, ap);
    va_end (ap);
}
