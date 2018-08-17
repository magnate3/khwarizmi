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
#include <rte_ip_frag.h>

#include"ethernet.h"

#define unused(a) (void)(a)

#define BURST_SIZE 32

struct rte_mempool *mp;

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

/* fragmentation */
void lcore_fragmentation_main(uint16_t *port_num) {
	/* rx_queue */
	struct rte_mempool *direct_pool;
	struct rte_mempool *indirect_pool;
	struct ethernet_hdr eth;

	int socket, frag_num;
	socket = rte_lcore_to_socket_id(rte_lcore_id());

	direct_pool  = rte_pktmbuf_pool_create("direct_pool", 8192, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket);
	indirect_pool  = rte_pktmbuf_pool_create("indirect_pool", 8192, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, socket);

	struct rte_mbuf *rx_mbufs[BURST_SIZE];
	
	while (1) {
		uint16_t nb_rx = rte_eth_rx_burst(*port_num, 0, rx_mbufs, BURST_SIZE);

		for (int i = 0; i < nb_rx; i++) {
			struct rte_mbuf *tx_mbufs[BURST_SIZE];
			rte_pktmbuf_dump(stdout, rx_mbufs[i], rte_pktmbuf_pkt_len(rx_mbufs[i]));
			uint8_t *p = rte_pktmbuf_mtod(rx_mbufs[i], uint8_t*);
			memcpy(&eth, p, 14); //eth header
			
			rte_pktmbuf_adj(rx_mbufs[i], (uint16_t)sizeof(struct ether_hdr));
			frag_num = rte_ipv4_fragment_packet(rx_mbufs[i], tx_mbufs, BURST_SIZE, 1500, direct_pool, indirect_pool);
			printf("frag_num: %d\n", frag_num);
			if (frag_num < 0) {
				rte_exit(EXIT_FAILURE, "frag error\n");
			}
			printf("=== frag pkts ===\n");
			for (int j = 0; j < frag_num; j++) {
				printf("----------------\n");
				uint8_t *pp = rte_pktmbuf_prepend(tx_mbufs[j], (uint16_t)sizeof(struct ethernet_hdr));
				memcpy(pp, &eth, 14);
				//rte_pktmbuf_linearize(tx_mbufs[j]);
				rte_pktmbuf_dump(stdout, tx_mbufs[j], rte_pktmbuf_pkt_len(tx_mbufs[j]));
			}
			printf("=================\n");
			
			uint16_t nb_tx = rte_eth_tx_burst(*port_num ^ 1, 0, tx_mbufs, 1);
			if (nb_tx < nb_rx) {
				for (int k = nb_tx; k < nb_rx ;k++) {
					printf("free\n");
					rte_pktmbuf_free(tx_mbufs[k]);
				}
			}
		}
	}
}
int launch_fragmentation_main(void *arg) {
	unsigned lcore_id = rte_lcore_id();
	printf("lcore%u launched\n", lcore_id);

	lcore_fragmentation_main((uint16_t *)arg);
	return 0;
}

/* reassemble */
void lcore_reassemble_main(uint16_t *port_num) {
	printf("reassemble\n");
	struct rte_mbuf *rx_mbufs[BURST_SIZE];
	//struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);

	while (1) {
		uint16_t nb_rx = rte_eth_rx_burst(*port_num, 0, rx_mbufs, 1);
	
		if (nb_rx > 0) {
			for (int i = 1; i < nb_rx; i++) {
				rte_pktmbuf_chain(rx_mbufs[0], rx_mbufs[i]);
				rte_pktmbuf_free(rx_mbufs[i]);
			}
			uint16_t nb_tx = rte_eth_tx_burst(*port_num ^ 1, 0, (struct rte_mbuf**)rx_mbufs, 1);
			rte_pktmbuf_free(rx_mbufs[0]);
		}
	}
}
int launch_reassemble_main(void *arg) {
	unsigned lcore_id = rte_lcore_id();
	printf("lcore%u launched\n", lcore_id);

	lcore_fragmentation_main((uint16_t *)arg);
	return 0;
}

int main(int argc, char **argv)
{
	printf("init\n");
  int ret = rte_eal_init(argc, argv);
  if (ret < 0) rte_exit(EXIT_FAILURE, "Invalid EAL parameters\n");

	printf("mempool\n");
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

	uint16_t port0 = 0;
	uint16_t port1 = 1;
	//rte_eal_remote_launch(launch_fragmentation_main, (void *)&port0, 1);
	//rte_eal_remote_launch(launch_reassemble_main, (void *)&port1, 2);
	printf("launch\n");
	//lcore_reassemble_main(&port0);
	lcore_fragmentation_main(&port0);

#if 0
  struct rte_mbuf* m0 = rte_pktmbuf_alloc(mp);
  struct rte_mbuf* m1 = rte_pktmbuf_alloc(mp);
  struct rte_mbuf* m2 = rte_pktmbuf_alloc(mp);
  uint8_t buf0[100], buf1[100], buf2[100];
  memset(buf0, 0x11, sizeof(buf0));
  memset(buf1, 0x22, sizeof(buf1));
  memset(buf2, 0x33, sizeof(buf2));
  mbuf_set(m0, buf0, sizeof(buf0));
  mbuf_set(m1, buf1, sizeof(buf1));
  mbuf_set(m2, buf2, sizeof(buf2));

  rte_pktmbuf_chain(m0, m1);
  rte_pktmbuf_chain(m0, m2);
  rte_pktmbuf_dump(stdout, m0, rte_pktmbuf_pkt_len(m0));

  int ntx = rte_eth_tx_burst(0, 0, (struct rte_mbuf**)&m0, 1);
  if (ntx != 1) rte_exit(EXIT_FAILURE, "tx_burst\n");

  rte_pktmbuf_free(m0);
  rte_pktmbuf_free(m1);
  rte_mempool_free(mp);
#endif
	rte_eal_wait_lcore(1);
	rte_eal_wait_lcore(2);
  rte_mempool_free(mp);
  return 0;
}

