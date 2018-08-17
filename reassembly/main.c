
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <rte_eal.h>
#include <rte_ethdev.h>
#include <rte_common.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#include <rte_ip_frag.h>

#include"include/ethernet.h"
#include"include/ip.h"

#define BURST_SIZE 32
#define unused(a) (void)(a)


static void port_configure(uint8_t port, size_t nb_rxq, size_t nb_txq,
      const struct rte_eth_conf* port_conf, struct rte_mempool* mp)
{
  const size_t rx_ring_size = 128;
  const size_t tx_ring_size = 512;

  int ret = rte_eth_dev_configure(port, nb_rxq, nb_txq, port_conf);
  if (ret < 0) rte_exit(EXIT_FAILURE, "rte_eth_dev_configure\n");

  for (size_t q=0; q<nb_rxq; q++) {
    int ret = rte_eth_rx_queue_setup(port, q, rx_ring_size,
        rte_eth_dev_socket_id(port), NULL, mp);
    if (ret < 0) rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup\n");
  }

  for (size_t q=0; q<nb_txq; q++) {
    struct rte_eth_txconf txconf;
    memset(&txconf, 0x0, sizeof(txconf));
    txconf.txq_flags &= ~ETH_TXQ_FLAGS_NOMULTSEGS;
    int ret = rte_eth_tx_queue_setup(port, q, tx_ring_size,
        rte_eth_dev_socket_id(port), &txconf);
    if (ret < 0) rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup\n");
  }

  ret = rte_eth_dev_start(port);
  if (ret < 0) rte_exit(EXIT_FAILURE, "rte_eth_dev_start\n");
  rte_eth_promiscuous_enable(port);
}

static inline void
mbuf_set(struct rte_mbuf* m, uint8_t* ptr, size_t len)
{
  m->pkt_len = len;
  m->data_len = len;
  rte_memcpy(rte_pktmbuf_mtod(m, uint8_t*), ptr, len);
}

int main(int argc, char **argv)
{
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

  struct rte_mempool* mp = NULL;
  mp = rte_pktmbuf_pool_create("mp", 8192, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, 0);
  if (!mp) rte_exit(EXIT_FAILURE, "Invalid MP parameters\n");

  struct rte_eth_conf port_conf;
  memset(&port_conf, 0, sizeof(struct rte_eth_conf));
  port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
  port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_LEN;
  port_conf.rxmode.header_split = 0;
  port_conf.rxmode.jumbo_frame = 1;
  port_conf.rxmode.enable_scatter = 1;
  port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;
  port_configure(0,1,1,&port_conf,mp);
  port_configure(1,1,1,&port_conf,mp);

	struct rte_mbuf *rx_mbufs[BURST_SIZE];
	int head_flag = 0;
	struct rte_mbuf *head_mbuf;
	while (1) {
		uint16_t nb_rx = rte_eth_rx_burst(0, 0, rx_mbufs, BURST_SIZE);
		if(nb_rx > 0) {
			for (int i = 0; i < nb_rx; i++) {
				uint8_t *p = rte_pktmbuf_mtod(rx_mbufs[i], uint8_t*);
				size_t size = rte_pktmbuf_pkt_len(rx_mbufs[i]);
				p += sizeof(struct ethernet_hdr);
				struct ip_hdr *iphdr = (struct ip_hdr *)p;
				if (rte_ipv4_frag_pkt_is_fragmented((struct ipv4_hdr *)iphdr)) {
					if (head_flag == 0) {
						head_flag = 1;
						head_mbuf = rx_mbufs[i];
						continue;
					}
					size_t p_size = rte_pktmbuf_pkt_len(rx_mbufs[i]);
					p_size -= sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr);
					
					struct ipv4_hdr *hdr = (struct ipv4_hdr *)iphdr;
					uint16_t flag = rte_be_to_cpu_16(hdr->fragment_offset);
					flag = flag & IPV4_HDR_MF_FLAG;
					rte_pktmbuf_adj(rx_mbufs[i], (uint16_t)(sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr)));
					rte_pktmbuf_chain(head_mbuf, rx_mbufs[i]);


					if (!flag) {
						rte_pktmbuf_dump(stdout, head_mbuf, 0);
						printf("tx_burst\n");
						struct ip_hdr *iphdr; 
						uint8_t *pt = rte_pktmbuf_mtod(head_mbuf, uint8_t*);
						pt += sizeof(struct ethernet_hdr);
						iphdr = (struct ip_hdr *)pt;
						iphdr->total_len = htons(rte_pktmbuf_pkt_len(head_mbuf) - 14);
						uint16_t nb_tx = rte_eth_tx_burst(1, 0, (struct rte_mbuf**)&head_mbuf, 1);
						
						printf("%u\n",nb_tx);
						head_flag = 0;
					}
				}
			}
		}
	}

  //struct rte_mbuf* m0 = rte_pktmbuf_alloc(mp);
  //struct rte_mbuf* m1 = rte_pktmbuf_alloc(mp);
  //struct rte_mbuf* m2 = rte_pktmbuf_alloc(mp);
  //uint8_t buf0[100], buf1[100], buf2[100];
  //memset(buf0, 0x11, sizeof(buf0));
  //memset(buf1, 0x22, sizeof(buf1));
  //memset(buf2, 0x33, sizeof(buf2));
  //mbuf_set(m0, buf0, sizeof(buf0));
  //mbuf_set(m1, buf1, sizeof(buf1));
  //mbuf_set(m2, buf2, sizeof(buf2));

  //rte_pktmbuf_chain(m0, m1);
  //rte_pktmbuf_chain(m0, m2);
  ///* rte_pktmbuf_linearize(m0); */
  //rte_pktmbuf_dump(stdout, m0, rte_pktmbuf_pkt_len(m0));

  //int ntx = rte_eth_tx_burst(0, 0, (struct rte_mbuf**)&m0, 1);
  //if (ntx != 1) rte_exit(EXIT_FAILURE, "tx_burst\n");

  //rte_pktmbuf_free(m0);
  //rte_pktmbuf_free(m1);
  rte_mempool_free(mp);
  return 0;
}

