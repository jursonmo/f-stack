/*
 * Copyright (C) 2017 THL A29 Limited, a Tencent company.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 *   list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <stdlib.h>
#include <arpa/inet.h>
#include <netinet/icmp6.h>

#include <rte_config.h>
#include <rte_ether.h>
#include <rte_bus_pci.h>
#include <rte_ethdev.h>
#include <rte_kni.h>
#include <rte_malloc.h>
#include <rte_ring.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>

#include "ff_dpdk_kni.h"
#include "ff_config.h"

/* Callback for request of changing MTU */
/* Total octets in ethernet header */
#define KNI_ENET_HEADER_SIZE    14

/* Total octets in the FCS */
#define KNI_ENET_FCS_SIZE       4

#define set_bit(n, m)   (n | magic_bits[m])
#define clear_bit(n, m) (n & (~magic_bits[m]))
#define get_bit(n, m)   (n & magic_bits[m])

static const int magic_bits[8] = {
    0x80, 0x40, 0x20, 0x10,
    0x8, 0x4, 0x2, 0x1
};

static unsigned char *udp_port_bitmap = NULL;
static unsigned char *tcp_port_bitmap = NULL;

/* Structure type for recording kni interface specific stats */
struct kni_interface_stats {
    struct rte_kni *kni;

    /* number of pkts received from NIC, and sent to KNI */
    uint64_t rx_packets;

    /* number of pkts received from NIC, but failed to send to KNI */
    uint64_t rx_dropped;

    /* number of pkts received from KNI, and sent to NIC */
    uint64_t tx_packets;

    /* number of pkts received from KNI, but failed to send to NIC */
    uint64_t tx_dropped;
};

struct rte_ring **kni_rp;
struct kni_interface_stats **kni_stat;

static void
set_bitmap(uint16_t port, unsigned char *bitmap)
{
    port = htons(port);
    unsigned char *p = bitmap + port/8;
    *p = set_bit(*p, port % 8);
}

static int
get_bitmap(uint16_t port, unsigned char *bitmap)
{
    unsigned char *p = bitmap + port/8;
    return get_bit(*p, port % 8) > 0 ? 1 : 0;
}

static void
kni_set_bitmap(const char *p, unsigned char *port_bitmap)
{
    int i;
    const char *head, *tail, *tail_num;
    if(!p)
        return;

    head = p;
    while (1) {
        tail = strstr(head, ",");
        tail_num = strstr(head, "-");
        if(tail_num && (!tail || tail_num < tail - 1)) {
            for(i = atoi(head); i <= atoi(tail_num + 1); ++i) {
                set_bitmap(i, port_bitmap);
            }
        } else {
            set_bitmap(atoi(head), port_bitmap);
        }

        if(!tail)
            break;

        head = tail + 1;
    }
}

/* Currently we don't support change mtu. */
static int
kni_change_mtu(uint16_t port_id, unsigned new_mtu)
{
    return 0;
}

static int
kni_config_network_interface(uint16_t port_id, uint8_t if_up)
{
    int ret = 0;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    printf("Configure network interface of %d %s\n",
            port_id, if_up ? "up" : "down");

    ret = (if_up) ?
        rte_eth_dev_set_link_up(port_id) :
        rte_eth_dev_set_link_down(port_id);

    if(-ENOTSUP == ret) {
        if (if_up != 0) {
            /* Configure network interface up */
            rte_eth_dev_stop(port_id);
            ret = rte_eth_dev_start(port_id);
        } else {
            /* Configure network interface down */
            rte_eth_dev_stop(port_id);
            ret = 0;
        }
    }

    if (ret < 0)
        printf("Failed to Configure network interface of %d %s\n", 
            port_id, if_up ? "up" : "down");

    return ret;
}

static void
print_ethaddr(const char *name, struct rte_ether_addr *mac_addr)
{
    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, mac_addr);
    printf("\t%s%s\n", name, buf);
}


/* Callback for request of configuring mac address */
static int
kni_config_mac_address(uint16_t port_id, uint8_t mac_addr[])
{
    int ret = 0;

    if (!rte_eth_dev_is_valid_port(port_id)) {
        printf("Invalid port id %d\n", port_id);
        return -EINVAL;
    }

    print_ethaddr("Address:", (struct rte_ether_addr *)mac_addr);

    ret = rte_eth_dev_default_mac_addr_set(port_id,
                       (struct rte_ether_addr *)mac_addr);
    if (ret < 0)
        printf("Failed to config mac_addr for port %d\n", port_id);

    return ret;
}

static int
kni_process_tx(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    /* read packet from kni ring(phy port) and transmit to kni */
    uint16_t nb_tx, nb_kni_tx;
    nb_tx = rte_ring_dequeue_burst(kni_rp[port_id], (void **)pkts_burst, count, NULL);

    /* NB.
     * if nb_tx is 0,it must call rte_kni_tx_burst
     * must Call regularly rte_kni_tx_burst(kni, NULL, 0).
     * detail https://embedded.communities.intel.com/thread/6668
     */
    nb_kni_tx = rte_kni_tx_burst(kni_stat[port_id]->kni, pkts_burst, nb_tx);
    rte_kni_handle_request(kni_stat[port_id]->kni);
    if(nb_kni_tx < nb_tx) {
        uint16_t i;
        for(i = nb_kni_tx; i < nb_tx; ++i)
            rte_pktmbuf_free(pkts_burst[i]);

        kni_stat[port_id]->rx_dropped += (nb_tx - nb_kni_tx);
    }

    kni_stat[port_id]->rx_packets += nb_kni_tx;
    return 0;
}

static int
kni_process_rx(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    uint16_t nb_kni_rx, nb_rx;

    /* read packet from kni, and transmit to phy port */
    nb_kni_rx = rte_kni_rx_burst(kni_stat[port_id]->kni, pkts_burst, count);
    if (nb_kni_rx > 0) {
        nb_rx = rte_eth_tx_burst(port_id, queue_id, pkts_burst, nb_kni_rx);
        if (nb_rx < nb_kni_rx) {
            uint16_t i;
            for(i = nb_rx; i < nb_kni_rx; ++i)
                rte_pktmbuf_free(pkts_burst[i]);

            kni_stat[port_id]->tx_dropped += (nb_kni_rx - nb_rx);
        }

        kni_stat[port_id]->tx_packets += nb_rx;
    }
    return 0;
}

static enum FilterReturn
protocol_filter_l4(uint16_t port, unsigned char *bitmap)
{
    if(get_bitmap(port, bitmap)) {
        return FILTER_KNI;
    }

    return FILTER_UNKNOWN;
}

static enum FilterReturn
protocol_filter_tcp(const void *data, uint16_t len)
{
    if (len < sizeof(struct rte_tcp_hdr))
        return FILTER_UNKNOWN;

    const struct rte_tcp_hdr *hdr;
    hdr = (const struct rte_tcp_hdr *)data;

    return protocol_filter_l4(hdr->dst_port, tcp_port_bitmap);
}

static enum FilterReturn
protocol_filter_udp(const void* data,uint16_t len)
{
    if (len < sizeof(struct rte_udp_hdr))
        return FILTER_UNKNOWN;

    const struct rte_udp_hdr *hdr;
    hdr = (const struct rte_udp_hdr *)data;

    return protocol_filter_l4(hdr->dst_port, udp_port_bitmap);
}

#ifdef INET6
/*
 * https://www.iana.org/assignments/ipv6-parameters/ipv6-parameters.xhtml
 */
#ifndef IPPROTO_HIP
#define IPPROTO_HIP 139
#endif

#ifndef IPPROTO_SHIM6
#define IPPROTO_SHIM6   140
#endif

#ifndef IPPROTO_MH
#define IPPROTO_MH   135
#endif
static int
get_ipv6_hdr_len(uint8_t *proto, void *data, uint16_t len)
{
    int ext_hdr_len = 0;

    switch (*proto) {
        case IPPROTO_HOPOPTS:   case IPPROTO_ROUTING:   case IPPROTO_DSTOPTS:
        case IPPROTO_MH:        case IPPROTO_HIP:       case IPPROTO_SHIM6:
            ext_hdr_len = *((uint8_t *)data + 1) + 1;
            break;
        case IPPROTO_FRAGMENT:
            ext_hdr_len = 8;
            break;
        case IPPROTO_AH:
            ext_hdr_len = (*((uint8_t *)data + 1) + 2) * 4;
            break;
        case IPPROTO_NONE:
#ifdef FF_IPSEC
        case IPPROTO_ESP:
            //proto = *((uint8_t *)data + len - 1 - 4);
            //ext_hdr_len = len;
#endif
        default:
            return ext_hdr_len;
    }

    if (ext_hdr_len >= len) {
        return len;
    }

    *proto = *((uint8_t *)data);
    ext_hdr_len += get_ipv6_hdr_len(proto, data + ext_hdr_len, len - ext_hdr_len);

    return ext_hdr_len;
}

static enum FilterReturn
protocol_filter_icmp6(void *data, uint16_t len)
{
    if (len < sizeof(struct icmp6_hdr))
        return FILTER_UNKNOWN;

    const struct icmp6_hdr *hdr;
    hdr = (const struct icmp6_hdr *)data;

    if (hdr->icmp6_type >= ND_ROUTER_SOLICIT && hdr->icmp6_type <= ND_REDIRECT)
        return FILTER_NDP;

    return FILTER_UNKNOWN;
}
#endif

static enum FilterReturn
protocol_filter_ip(const void *data, uint16_t len, uint16_t eth_frame_type)
{
    uint8_t proto;
    int hdr_len;
    void *next;
    uint16_t next_len;

    if (eth_frame_type == RTE_ETHER_TYPE_IPV4) {
        if(len < sizeof(struct rte_ipv4_hdr))
            return FILTER_UNKNOWN;

        const struct rte_ipv4_hdr *hdr = (struct rte_ipv4_hdr *)data;
        hdr_len = (hdr->version_ihl & 0x0f) << 2;
        if (len < hdr_len)
            return FILTER_UNKNOWN;

        proto = hdr->next_proto_id;
#ifdef INET6
    } else if(eth_frame_type == RTE_ETHER_TYPE_IPV6) {
        if(len < sizeof(struct rte_ipv6_hdr))
            return FILTER_UNKNOWN;

        hdr_len = sizeof(struct rte_ipv6_hdr);
        proto = ((struct rte_ipv6_hdr *)data)->proto;
        hdr_len += get_ipv6_hdr_len(&proto, (void *)data + hdr_len, len - hdr_len);

        if (len < hdr_len)
            return FILTER_UNKNOWN;
#endif
    } else {
        return FILTER_UNKNOWN;
    }

    next = (void *)data + hdr_len;
    next_len = len - hdr_len;

    switch (proto) {
        case IPPROTO_TCP:
#ifdef FF_KNI
            if (!enable_kni)
                break;
#else
            break;
#endif
            return protocol_filter_tcp(next, next_len);
        case IPPROTO_UDP:
#ifdef FF_KNI
            if (!enable_kni)
                break;
#else
            break;
#endif
            return protocol_filter_udp(next, next_len);
        case IPPROTO_IPIP:
            return protocol_filter_ip(next, next_len, RTE_ETHER_TYPE_IPV4);
#ifdef INET6
        case IPPROTO_IPV6:
            return protocol_filter_ip(next, next_len, RTE_ETHER_TYPE_IPV6);
        case IPPROTO_ICMPV6:
            return protocol_filter_icmp6(next, next_len);
#endif
    }

    return FILTER_UNKNOWN;
}

enum FilterReturn
ff_kni_proto_filter(const void *data, uint16_t len, uint16_t eth_frame_type)
{
    return protocol_filter_ip(data, len, eth_frame_type);
}

void
ff_kni_init(uint16_t nb_ports, const char *tcp_ports, const char *udp_ports)
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        kni_stat = rte_zmalloc("kni:stat",
            sizeof(struct kni_interface_stats *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
        if (kni_stat == NULL)
            rte_exit(EXIT_FAILURE, "rte_zmalloc(1 (struct netio_kni_stat *)) "
                "failed\n");

        rte_kni_init(nb_ports);
    }

    uint16_t lcoreid = rte_lcore_id();
    char name_buf[RTE_RING_NAMESIZE];
    snprintf(name_buf, RTE_RING_NAMESIZE, "kni::ring_%d", lcoreid);
    kni_rp = rte_zmalloc(name_buf,
            sizeof(struct rte_ring *) * nb_ports,
            RTE_CACHE_LINE_SIZE);
    if (kni_rp == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (struct rte_ring*)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:tcp_port_bitmap_%d", lcoreid);
    tcp_port_bitmap = rte_zmalloc("kni:tcp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (tcp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (tcp_port_bitmap)) "
                "failed\n", name_buf);
    }

    snprintf(name_buf, RTE_RING_NAMESIZE, "kni:udp_port_bitmap_%d", lcoreid);
    udp_port_bitmap = rte_zmalloc("kni:udp_port_bitmap", 8192,
        RTE_CACHE_LINE_SIZE);
    if (udp_port_bitmap == NULL) {
        rte_exit(EXIT_FAILURE, "rte_zmalloc(%s (udp_port_bitmap)) "
                "failed\n",name_buf);
    }

    memset(tcp_port_bitmap, 0, 8192);
    memset(udp_port_bitmap, 0, 8192);

    kni_set_bitmap(tcp_ports, tcp_port_bitmap);
    kni_set_bitmap(udp_ports, udp_port_bitmap);
}

void
ff_kni_alloc(uint16_t port_id, unsigned socket_id,
    struct rte_mempool *mbuf_pool, unsigned ring_queue_size)
{
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        struct rte_kni_conf conf;
        struct rte_kni_ops ops;
        struct rte_eth_dev_info dev_info;
        const struct rte_pci_device *pci_dev;
        const struct rte_bus *bus = NULL;

        kni_stat[port_id] = (struct kni_interface_stats*)rte_zmalloc(
            "kni:stat_lcore",
            sizeof(struct kni_interface_stats),
            RTE_CACHE_LINE_SIZE);

        if (kni_stat[port_id] == NULL)
            rte_panic("rte_zmalloc kni_interface_stats failed\n");

        /* only support one kni */
        memset(&conf, 0, sizeof(conf));
        snprintf(conf.name, RTE_KNI_NAMESIZE, "veth%u", port_id);
        conf.core_id = rte_lcore_id();
        conf.force_bind = 1;
        conf.group_id = port_id;
        uint16_t mtu;
        rte_eth_dev_get_mtu(port_id, &mtu);
        conf.mbuf_size = mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;

        memset(&dev_info, 0, sizeof(dev_info));
        rte_eth_dev_info_get(port_id, &dev_info);

        if (dev_info.device)
            bus = rte_bus_find_by_device(dev_info.device);
        if (bus && !strcmp(bus->name, "pci")) {
            pci_dev = RTE_DEV_TO_PCI(dev_info.device);
            conf.addr = pci_dev->addr;
            conf.id = pci_dev->id;
        }
        
        /* Get the interface default mac address */
        rte_eth_macaddr_get(port_id,
                (struct rte_ether_addr *)&conf.mac_addr);

        memset(&ops, 0, sizeof(ops));
        ops.port_id = port_id;
        ops.change_mtu = kni_change_mtu;
        ops.config_network_if = kni_config_network_interface;
        ops.config_mac_address = kni_config_mac_address;

        kni_stat[port_id]->kni = rte_kni_alloc(mbuf_pool, &conf, &ops);
        if (kni_stat[port_id]->kni == NULL)
            rte_panic("create kni on port %u failed!\n", port_id);
        else
            printf("create kni on port %u success!\n", port_id);

        kni_stat[port_id]->rx_packets = 0;
        kni_stat[port_id]->rx_dropped = 0;
        kni_stat[port_id]->tx_packets = 0;
        kni_stat[port_id]->tx_dropped = 0;
    }

    char ring_name[RTE_KNI_NAMESIZE];
    snprintf((char*)ring_name, RTE_KNI_NAMESIZE, "kni_ring_%u", port_id);

    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
        kni_rp[port_id] = rte_ring_create(ring_name, ring_queue_size, 
            socket_id, RING_F_SC_DEQ);

        if (rte_ring_lookup(ring_name) != kni_rp[port_id])
            rte_panic("lookup kni ring failed!\n");
    } else {
        kni_rp[port_id] = rte_ring_lookup(ring_name);
    }

    if (kni_rp[port_id] == NULL)
        rte_panic("create kni ring failed!\n");

    printf("create kni ring success, %u ring entries are now free!\n",
        rte_ring_free_count(kni_rp[port_id]));
}

void
ff_kni_process(uint16_t port_id, uint16_t queue_id,
    struct rte_mbuf **pkts_burst, unsigned count)
{
    kni_process_tx(port_id, queue_id, pkts_burst, count);
    kni_process_rx(port_id, queue_id, pkts_burst, count);
}

/* enqueue the packet, and own it */
int
ff_kni_enqueue(uint16_t port_id, struct rte_mbuf *pkt)
{
    int ret = rte_ring_enqueue(kni_rp[port_id], pkt);
    if (ret < 0)
        rte_pktmbuf_free(pkt);

    return 0;
}


//---------------------------mykni-----------------------
/* kni device statistics array */
static struct kni_interface_stats kni_stats[RTE_MAX_ETHPORTS];
/* Max size of a single packet */
#define MAX_PACKET_SZ           2048

/* Size of the data buffer in each mbuf */
#define MBUF_DATA_SZ (MAX_PACKET_SZ + RTE_PKTMBUF_HEADROOM)

/* Number of mbufs in mempool that is created */
//#define NB_MBUF                 (8192 * 16)
#define NB_MBUF                 (8192 * 1)

/* How many packets to attempt to read from NIC in one go */
#define PKT_BURST_SZ            32

/* How many objects (mbufs) to keep in per-lcore mempool cache */
#define MEMPOOL_CACHE_SZ        PKT_BURST_SZ

#define KNI_MAX_KTHREAD 32
/*
 * Structure of port parameters
 */
struct kni_port_params {
	uint16_t port_id;/* Port ID */
	unsigned lcore_rx; /* lcore ID for RX */
	unsigned lcore_tx; /* lcore ID for TX */
	uint32_t nb_lcore_k; /* Number of lcores for KNI multi kernel threads */
	uint32_t nb_kni; /* Number of KNI devices to be created */
	unsigned lcore_k[KNI_MAX_KTHREAD]; /* lcore ID list for kthreads */
	struct rte_kni *kni[KNI_MAX_KTHREAD]; /* KNI context pointers */
} __rte_cache_aligned;

/* Mempool for mbufs */
//extern struct rte_mempool *pktmbuf_pool[NB_SOCKETS];
static struct rte_mempool *pktmbuf_pool[RTE_MAX_ETHPORTS];
static struct kni_port_params *kni_port_params_array[RTE_MAX_ETHPORTS];
int port_id = 0;
struct rte_mbuf *pkts_burst_tx[PKT_BURST_SZ];
struct rte_mbuf *pkts_burst_rx[PKT_BURST_SZ];
int nb_tx = 0;
int nb_rx = 0;
int rx_index = 0;


/* Initialize KNI subsystem */
void
ff_init_mykni(void)
{
    /*
	unsigned int num_of_kni_ports = 0, i;
	struct kni_port_params **params = kni_port_params_array;

	// Calculate the maximum number of KNI interfaces that will be used 
	for (i = 0; i < RTE_MAX_ETHPORTS; i++) {
		if (kni_port_params_array[i]) {
			num_of_kni_ports += (params[i]->nb_lcore_k ?
				params[i]->nb_lcore_k : 1);
		}
	}
    */
	/* Invoke rte KNI init to preallocate the ports */
    unsigned int num_of_kni_ports = 0;
	rte_kni_init(num_of_kni_ports);
}

int
ff_mykni_env() { 
    char s[64] = {0};
    unsigned int socketid;
    void *b = NULL;
    struct kni_port_params *c;
    struct rte_mbuf *mb;
    memset(&kni_port_params_array, 0, sizeof(kni_port_params_array));
    printf("RTE_MAX_ETHPORTS =%d , port_id=%d\n", RTE_MAX_ETHPORTS, port_id);
    
	b = rte_zmalloc("KNI_port_params",
				    sizeof(struct kni_port_params), RTE_CACHE_LINE_SIZE);
    if (!b) {
        rte_exit(EXIT_FAILURE, "Could not rte_zmalloc KNI_port_params\n");
        return -1;
    }

    kni_port_params_array[port_id] = (struct kni_port_params*)b;                         
    kni_port_params_array[port_id]->port_id = (uint16_t)port_id;

    socketid = rte_socket_id();
    printf("start rte_pktmbuf_pool_create, socket=%d\n", socketid);
    snprintf(s, sizeof(s), "mbuf_pool_mykni_%d", socketid);
    if (rte_eal_process_type() == RTE_PROC_PRIMARY) {
         /* Create the mbuf pool */        
        pktmbuf_pool[port_id] = rte_pktmbuf_pool_create(s, NB_MBUF,
            MEMPOOL_CACHE_SZ, 0, MBUF_DATA_SZ, socketid);

        if (rte_mempool_lookup(s)!= pktmbuf_pool[port_id]){
            rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool:%s\n", s);
            return -1;
	    }
    } else {
        pktmbuf_pool[port_id] = rte_mempool_lookup(s);
    }   
	if (pktmbuf_pool[port_id] == NULL) {
		rte_exit(EXIT_FAILURE, "Could not initialise mbuf pool\n");
		return -1;
	}

    //testing
    //mb = rte_mbuf_raw_alloc(pktmbuf_pool[port_id]);
    mb = rte_pktmbuf_alloc(pktmbuf_pool[port_id]);
    if (!mb) {
        rte_exit(EXIT_FAILURE, "Could not alloc mbuf from pool\n");
		return -1;
    }
    printf("mb: pkt_len:%d, data_len:%d, data_off:%d, buf_len:%d \n", mb->pkt_len, mb->data_len, mb->data_off, mb->buf_len);
    //output: mb: pkt_len:0, data_len:0, data_off:128, buf_len:2176
    rte_pktmbuf_free(mb);

    kni_stats[port_id].rx_packets = 0;
    kni_stats[port_id].rx_dropped = 0;
    kni_stats[port_id].tx_packets = 0;
    kni_stats[port_id].tx_dropped = 0;
    return 0;
}

int ff_mykni_alloc()
{
	uint8_t i = 0;
	struct rte_kni *kni;
	struct rte_kni_conf conf;
    struct kni_port_params **params = kni_port_params_array;
    struct rte_kni_ops ops;
    
    snprintf(conf.name, RTE_KNI_NAMESIZE,
					"moveth%u_%u", port_id, i);
    //conf.min_mtu = 1000;//dev_info.min_mtu;
	//conf.max_mtu = 1500;//dev_info.max_mtu;
    conf.group_id = port_id;
    //rte_eth_dev_get_mtu(port_id, &mtu);
    //conf.mbuf_size = mtu + KNI_ENET_HEADER_SIZE + KNI_ENET_FCS_SIZE;
    // if tso,maybe ptk will be drop in kernel becase mbuf_size too small, and show on dev stats tx_dropped
	conf.mbuf_size = MAX_PACKET_SZ;conf.core_id = 1;//rte_lcore_id();
	conf.force_bind = 1;

    memset(&ops, 0, sizeof(ops));
	ops.port_id = port_id;
    
    kni = rte_kni_alloc(pktmbuf_pool[port_id], &conf, &ops);
    if (!kni)
        rte_exit(EXIT_FAILURE, "Fail to create kni for "
                    "port: %d\n", port_id);
    params[port_id]->kni[i] = kni;
    return 0;
}

int ff_sendto_mykni(char *buf, int len) {
    struct rte_kni *kni = kni_port_params_array[port_id]->kni[0];
    int nb_kni_tx = 0;
    struct rte_mbuf *mb = NULL;
    mb = rte_pktmbuf_alloc(pktmbuf_pool[port_id]);
    if (!mb) {
        return -1;
    }

    //memcpy(mb->buf_addr+mb->data_off, buf, len);
    rte_memcpy(rte_pktmbuf_mtod_offset(mb, char *, 0), buf, (size_t) len);
    // mb->next = NULL;
    // mb->nb_segs = 1;
    mb->pkt_len = len;
    mb->data_len = len;
    pkts_burst_tx[nb_rx] = mb;
    nb_tx++;

    if (nb_tx == PKT_BURST_SZ) {
        nb_kni_tx = rte_kni_tx_burst(kni, pkts_burst_tx, nb_tx);
        if (nb_kni_tx) {
            kni_stats[port_id].rx_packets += nb_kni_tx;
        }
        if(nb_kni_tx < nb_tx) {
            uint16_t i;
            for(i = nb_kni_tx; i < nb_tx; ++i)
                rte_pktmbuf_free(pkts_burst_tx[i]);
        
            kni_stats[port_id].rx_dropped += (nb_tx - nb_kni_tx);
        }
        nb_tx = 0;//reset
    }
    return 0;   
}

int ff_flush_mykni() {
    struct rte_kni *kni = kni_port_params_array[port_id]->kni[0];
    int nb_kni_tx = 0;
    if (nb_tx == 0) {
        return 0;
    }
    nb_kni_tx = rte_kni_tx_burst(kni, pkts_burst_tx, nb_tx);
    if (nb_kni_tx)
            kni_stats[port_id].rx_packets += nb_kni_tx;

    if(nb_kni_tx < nb_tx) {
        uint16_t i;
        for(i = nb_kni_tx; i < nb_tx; ++i)
            rte_pktmbuf_free(pkts_burst_tx[i]);
    
        kni_stats[port_id].rx_dropped += (nb_tx - nb_kni_tx);
    }
    nb_tx = 0;//reset
    return nb_kni_tx;
}

int ff_mykni_txbuf_len() {
    return nb_tx;
}

// return 0, means nb_rx == 0 and rx_index == 0
int get_data_from_rxbuf(char *buf, int cap) {
    struct rte_mbuf *mb = NULL;
    if (nb_rx){
        mb = pkts_burst_rx[rx_index];
        if (!mb){
            rte_exit(EXIT_FAILURE, "Could not be NULL, rx_index:%d, nb_rx:%d\n", rx_index, nb_rx);
            return -1;
        }
        if (mb->data_len > cap)
            return -1;
        rte_memcpy(buf, rte_pktmbuf_mtod(mb, char *), (size_t) mb->data_len);
        //rte_memcpy(buf, rte_pktmbuf_mtod_offset(mb, char *, 0), (size_t) mb->data_len);
        //rte_pktmbuf_data_len(m);
        //memcpy(buf, mb->buf_addr+mb->data_off, mb->data_len);
        rte_pktmbuf_free(mb);
        pkts_burst_rx[rx_index] = NULL;
        nb_rx--;
        if (nb_rx)
            rx_index++;
        else 
            rx_index = 0;

        return mb->data_len;
    }

    //no data ? check 
    if (rx_index) {
        rte_exit(EXIT_FAILURE, "invaild, rx_index:%d, nb_rx:%d\n", rx_index, nb_rx);
        return -1;
    }
    return 0; //need to burst read
}

int ff_mykni_read(char *buf, int cap) {
    int len;
    if (!buf)
        return 0;

    len = get_data_from_rxbuf(buf, cap);
    if (!len){
        struct rte_kni *kni = kni_port_params_array[port_id]->kni[0];
        nb_rx = rte_kni_rx_burst(kni, pkts_burst_rx, sizeof(pkts_burst_rx));
        if (nb_rx)
            len = get_data_from_rxbuf(buf, cap);
    }
    return len;
}

int ff_mykni_read_multi(char **buf,int *data_len, int nb, int cap) {
    int i, len;
    int has_rx;
    for(i = 0; i < nb; i++ ) {
        if (!buf[i])
            break;

        len = get_data_from_rxbuf(buf[i], cap); 
        data_len[i] = len;
        if (!len && !has_rx){
            struct rte_kni *kni = kni_port_params_array[port_id]->kni[0];
            nb_rx = rte_kni_rx_burst(kni, pkts_burst_rx, sizeof(pkts_burst_rx));
            if (nb_rx)
                len = get_data_from_rxbuf(buf[i], cap);
            has_rx = 1;
        }
        // still no data, break loop
        if (!len)
            break;      
    }

    return i;
}

#define FDS_TABLE_SIZE_DEFAULT 16
int fds_table_size = 0;
struct list_head *fds_table;
struct fd_node {
    struct list_head    list;
    struct rte_ether_addr mac;
    int fd;
}__rte_cache_aligned;

void init_fds_table(int size){
    int i;
    fds_table_size = size;
    if (!fds_table_size)
        fds_table_size = FDS_TABLE_SIZE_DEFAULT;
    
    fds_table = rte_malloc_socket(NULL, sizeof(struct list_head) * fds_table_size,
            RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (fds_table == NULL)
        rte_exit(EXIT_FAILURE, "rte_zmalloc_socket:%d, sizeof(struct list_head) * fds_table_size) "
            "failed\n", rte_socket_id()); 

    for (i = 0; i < fds_table_size; i++)
        INIT_LIST_HEAD(&fds_table[i]);
}
// todo: destroy fds_table

void print_mac(struct rte_ether_addr *mac) {
    printf(" MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n\n",
		mac->addr_bytes[0],mac->addr_bytes[1],mac->addr_bytes[2],
				mac->addr_bytes[3],mac->addr_bytes[4],mac->addr_bytes[5]);
}

int mac_hash(struct rte_ether_addr *mac, int mask ) {
    return (mac->addr_bytes[0]+mac->addr_bytes[1]+mac->addr_bytes[2]+
				mac->addr_bytes[3]+mac->addr_bytes[4]+mac->addr_bytes[5])&mask;
}
//rte_ether_addr_copy, rte_is_same_ether_addr
int get_fd_by_mac(struct rte_ether_addr *mac) {
    int hash = mac_hash(mac, fds_table_size-1);
    struct fd_node *node;
    list_for_each_entry(node, &fds_table[hash], list) {
        if (rte_is_same_ether_addr(&node->mac, mac)) {
            return node->fd;
        }
    }
    return -1;
}

struct fd_node * get_node_by_mac(struct rte_ether_addr *mac) {
    int hash = mac_hash(mac, fds_table_size-1);
    struct fd_node *node;
    list_for_each_entry(node, &fds_table[hash], list) {
        if (rte_is_same_ether_addr(&node->mac, mac)) {
            return node;
        }
    }
    return NULL;
}

int get_fd_by_data(char *buf, int buf_len) {
    if (sizeof(struct rte_ether_hdr) < buf_len) {
        return -1;
    }
	struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buf;
    return get_fd_by_mac(&eth_hdr->d_addr);
}

int learn_fd_mac(char *buf, int buf_len, int fd) {
    if (sizeof(struct rte_ether_hdr) < buf_len) {
        return -1;
    }
    struct fd_node *node;
    struct rte_ether_hdr *eth_hdr = (struct rte_ether_hdr *)buf;    

    node = get_node_by_mac(&eth_hdr->s_addr);
    if (node) {
        if (node->fd == fd) 
            return 0;
        //update fd
        print_mac(&eth_hdr->s_addr);
        printf("fdb update: current fd:%d change to new fd:%d\n", node->fd, fd);
        node->fd = fd;
        return 1;
    }

    //new node
    node = rte_zmalloc_socket(NULL, sizeof(struct fd_node),
            RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (node == NULL)
        rte_exit(EXIT_FAILURE, "rte_zmalloc_socket:%d, sizeof(struct fd_node)) "
            "failed\n", rte_socket_id());
    rte_ether_addr_copy(&eth_hdr->s_addr, &node->mac);
    node->fd = fd;

    //add to fds_table
    int hash = mac_hash(&eth_hdr->s_addr, fds_table_size-1);
    list_add(&node->list, &fds_table[hash]);
    return 1;
}

#if 1
//power of two
struct iobuf {
    unsigned int head;
    unsigned int tail;
    //int size;
    int cap;//power of two
    int mask;
    int fd;
    ssize_t (*readv)(int fd, const struct iovec *iov, int iovcnt);
    char buf[0];
};

struct iobuf* create_iobuf(int cap, int fd) {
    if (cap & (cap -1)){
        printf("cap:%d is not power of two", cap)
        return NULL;
    }

    struct iobuf *ib = rte_zmalloc_socket(NULL, sizeof(struct iobuf)+cap,
            RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!ib)
        return ib;

    ib->cap = cap;
    ib->mask = cap-1;
    ib->fd = fd;
    ib->readv = ff_readv;
    return ib;
}

//return actually iovec counter
int get_iovs(struct iobuf *ib, struct iovec *iovs, int iovcnt) {
    int head = ib->head&ib->mask;
    int tail = ib->tail&ib->mask;
    char buf = ib->buf;
    int actual_iovcnt = 0;

    //no space
    if (ib->head == ib->tail)
        return 0;

    //0-->tail --> head--->cap
    if (head >= tail) {
        // head--->cap
        iovs[actual_iovcnt].iov_base = &buf[head];
        iovs[actual_iovcnt].iov_len = cap-head;
        actual_iovcnt++;
        if (tail > 0) {
            //buf is 0:tail
            iovs[actual_iovcnt].iov_base = buf;
            iovs[actual_iovcnt].iov_len = tail;
            actual_iovcnt++;
        }
        return actual_iovcnt
    }

    //0-->head-->tail--->cap
    if (head < tail) {
        iovs[actual_iovcnt].iov_base = &buf[head];
        iovs[actual_iovcnt].iov_len = tail-head;
        actual_iovcnt++;
        return actual_iovcnt;
    }
    //never be here
}

// do it after get data from iobuf
void iobuf_movetail(struct iobuf *ib, int n) {
    if (n <= 0) 
        return;
    
    // it is ok for ib->head wrap
    int size = ib->head - ib->tail;
    //iobuf_movetail means have got data, so n must < size
    if (ib->size < n)
        rte_exit(EXIT_FAILURE, "size(%d) < n(%d)\n", size, n); 
    
    ib->tail += n;
    return;
}

//do it after read data and put to iobuf, should move head
void iobuf_movehead(struct iobuf *ib, int n) {
    int head = ib->head;
    int tail = ib->tail;
    int cap = ib->cap;
    int size = ib->size;

    if (n == 0)
        return 0;

    int size = ib->head - ib->tail;
    //no space
    if (n > cap - size)
        rte_exit(EXIT_FAILURE, "n(%d) > cap(%d)-size(%d)\n",n , cap, size);
    
    ib->head += n;
    return;
}

int iobuf_readv(struct iobuf *ib){
    struct iovec iovs[2];
    int iovcnt = get_iovs(ib, iovs, 2);
    int read_len = ib->readv(ib->fd, iovs, iovcnt);//ff_readv
    // todo: ff_readv err case, 
    if (read_len == -1 )
        return read_len;

    iobuf_movehead(ib, read_len);
}

//must get fix len data 
int peek_iobuf_data(struct iobuf *ib, char *peek_buf, int len){
    int head, tail, size;
    int cap = ib->cap;
    char buf = ib->buf;
    int max_read = 1;
    int i = 0; 
    int ret = 0;

    //can't peek data bigger than iobuf cap
    if（cap < len) {
        printf("peek_iobuf_data: cap(%d) < len(%d)", cap, len)
        return 0
    }

    for ( i = 0; i <= max_read; i++) {
        head = ib->head&ib->mask;
        tail = ib->tail&ib->mask;
        size = ib->head - ib->tail;

        if (size < len) {
             //no enough data, read io 
            if ((ret = iobuf_readv(ib)) < 0)
                return ret;
            continue;
        }

        //have enough data in buf
        if (head > tail) {
            //check, must head - tail >= len
            if (head - tail < len)
                rte_exit(EXIT_FAILURE, "never happen: head(%d) -tail(%d) < len(%d) \n",head, tail, len);
            
            rte_memcpy(peek_buf, &buf[tail], len)
            return len;
        }

        //ib->head wrap
        if (head <= tail) {
            int contiguous = cap - tail;
            if ( contiguous >= len) {
                rte_memcpy(peek_buf, &buf[tail], len)
                return len;
            }
            // should copy tow contiguous memory
            rte_memcpy(peek_buf, &buf[tail], contiguous);
            rte_memcpy(&peek_buf[contiguous], buf, len-contiguous);
            return len;
        }
    }
    return 0;
}

int peek(struct iobuf *ib, char *buf, int len)
    return peek_iobuf_data(ib, buf, len);
}

int read(struct iobuf *ib, char *buf, int len) {
    int get_data_len = peek_iobuf_data(ib, buf, len);
    iobuf_movetail(get_data_len);
    return get_data_len;
}

#else
struct iobuf {
    int head;
    int tail;
    int size; // data len in buf
    int cap;
    int fd;
    char buf[0];
};

struct iobuf* create_iobuf(int cap, int fd) {
    struct iobuf *ib = rte_zmalloc_socket(NULL, sizeof(struct iobuf)+size,
            RTE_CACHE_LINE_SIZE, rte_socket_id());
    if (!ib)
        return ib;

    ib->cap = cap;
    ib->fd = fd;
    return ib;
}

//return actually iovec counter
int get_iovs(struct iobuf *ib, struct iovec *iovs, int iovcnt) {
    int head = ib->head;
    int tail = ib->tail;
    int cap = ib->cap;
    char buf = ib->buf;
    int actual_iovcnt = 0;

    //no space
    if (ib->size == cap)
        return 0;

    //0-->tail --> head--->cap
    if (head >= tail) {
        // head--->cap
        iovs[actual_iovcnt].iov_base = &buf[head];
        iovs[actual_iovcnt].iov_len = cap-head;
        actual_iovcnt++;
        if (tail > 0) {
            //buf is 0:tail
            iovs[actual_iovcnt].iov_base = buf;
            iovs[actual_iovcnt].iov_len = tail;
            actual_iovcnt++;
        }
        return actual_iovcnt
    }

    //0-->head-->tail--->cap
    if (head < tail) {
        iovs[actual_iovcnt].iov_base = &buf[head];
        iovs[actual_iovcnt].iov_len = tail-head;
        actual_iovcnt++;
        return actual_iovcnt;
    }
    //never be here
}

// do it after get data from iobuf
void iobuf_movetail(struct iobuf *ib, int n) {
    int head = ib->head;
    int tail = ib->tail;
    int cap = ib->cap;

    if (n <= 0) {
        return;
    }

    //must have data, and  n must < size
    if (ib->size < n)
        rte_exit(EXIT_FAILURE, "size(%d) < n(%d)\n", size, n); 
    
    if (head > tail) {
        ib->tail += n;
        ib->size -= n;
        return;
    }
    // head < tail or head == tail
    if (cap-tail > n) {
        ib->tail += n;
        return;
    }
    ib->tail = n-(cap-tail);
    ib->size -= n;
    return;
}

//do it after read data and put to iobuf
void iobuf_movehead(struct iobuf *ib, int n) {
    int head = ib->head;
    int tail = ib->tail;
    int cap = ib->cap;
    int size = ib->size;

    if (n == 0)
        return 0;

    //full
    //if (size == cap) 
    //    return 0;

    if (n > cap-size) {
        printf("unexpect case: no enough space, n(%d) > cap(%d)-size(%d)\n", n, cap, size); 
        return 0;
    }

    if (head > tail || (/*head == tail &&*/ size == 0 )) {
        if (head + n <= cap) {
            ib->head = head + n;
            if (ib->head == cap)
                ib->head = 0;

            ib->size += n;
            return n;
        }
        //wrap case
        head = n+head-cap;
        if (head > tail) 
            rte_exit(EXIT_FAILURE, "head(%d) > tail(%d)\n", head, tail); 
        
        ib->head = head;
        ib->size += n;
        return n;
    }

    //head < tail
    ib->head = head + n;
    ib->size += n;
    //check
    if (head > tail) 
        rte_exit(EXIT_FAILURE, "head(%d) > tail(%d)\n", head, tail);

    return n;
}

int iobuf_readv(struct iobuf *ib){
    struct iovec iovs[2];
    int iovcnt = get_iovs(ib, iovs, 2);
    int read_len = ff_readv(ib->fd, iovs, iovcnt);
    // todo: ff_readv err case, 
    if (read_len == -1 )
        return read_len;

    iobuf_movehead(ib, read_len);
}

int peek_iobuf_data(struct iobuf *ib, char *peek_buf, int len){
    int head = ib->head;
    int tail = ib->tail;
    int cap = ib->cap;  
    char buf = ib->buf;
    int max_read = 1;
    int i = 0; 
    int ret = 0;

    for ( i = 0; i <= max_read; i++) {
        int size = ib->size;
        if (size < len) {
             //no enough data, read io 
            if ((ret = iobuf_readv(ib)) < 0)
                return ret;
            continue;
        }

        //have enough data in buf
        if (head > tail) {
            //check, must head - tail >= len
            if (head - tail < len)
                rte_exit(EXIT_FAILURE, "never happen: head(%d) -tail(%d) < len(%d) \n",head, tail, len);
            
            rte_memcpy(peek_buf, &buf[tail], len)
            return len;
        }

        if (head < tail) {
            int contiguous = cap - tail;
            if ( contiguous >= len) {
                rte_memcpy(peek_buf, &buf[tail], len)
                return len;
            }
            // should copy tow contiguous memory
            rte_memcpy(peek_buf, &buf[tail], contiguous);
            rte_memcpy(&peek_buf[contiguous], buf, len-contiguous);
            return len;
        }

        #if 0
        if (head > tail) {
            if (head - tail > len){
                rte_memcpy(peek_buf, &buf[tail], len)
                return len;
            }
            //no enough data, read io 
            if ((ret = iobuf_readv(ib)) < 0)
                return ret;
            continue;
        }

        if (head < tail) {
            if (cap - (tail-head) > len) {
                rte_memcpy(peek_buf, &buf[tail], cap - tail);
                rte_memcpy(&peek_buf[cap-tail], buf, len-(cap - tail));
                return len;
            }
            //no enough data, read io 
            if ((ret = iobuf_readv(ib)) < 0)
                return ret;
            continue;
        }

        //emtpy
        if (head == tail && size == 0) {
            //no enough data, read io 
            if ((ret = iobuf_readv(ib)) < 0)
                return ret;
            continue;
        }

        //full
        if (head == tail ) {
            if (len > size)
                return 0;//too large peek_buf
            if (cap - tail > len) {
                rte_memcpy(peek_buf, &buf[tail], len);
            } else {
                rte_memcpy(peek_buf, &buf[tail], cap - tail);
                rte_memcpy(&peek_buf[cap-tail], buf, len-(cap - tail));
            }
            return len;
        }
        #endif
    }
}

int peek(struct iobuf *ib, char *buf, int len)
    return peek_iobuf_data(ib, buf, len);
}

int read(struct iobuf *ib, char *buf, int len) {
    int get_data_len = peek_iobuf_data(ib, buf, len);
    iobuf_movetail(get_data_len);
    return get_data_len;
}
#endif