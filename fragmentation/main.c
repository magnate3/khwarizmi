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

/* fragmentation */
void lcore_fragmentation_main(uint16_t port_num) {
	struct rte_mbuf *rx_mbuf[BURST_SIZE];

	uint16_t nb_tx = rte_eth_tx_burst(port_num, 0, rx_mbufs, 1);
}
int launch_lcore_fragmentation(void *arg) {
	unsigned lcore_id = rte_lcore_id();
	printf("lcore%u launched\n", lcore_id);

	lcore_fragmentation_main((uint16_t)arg);
	return 0;
}

/* reassemble */
void lcore_reassemble_main(uint16_t port_num) {
	struct rte_mbuf *rx_mbufs[BURST_SIZE];

	uint16_t nb_tx = rte_eth_tx_burst(port_num, 0, rx_mbufs, 1);
}
int launch_reassemble_main(void *arg) {
	unsigned lcore_id = rte_lcore_id();
	printf("lcore%u launched\n", lcore_id);

	lcore_fragmentation_main((uint16_t)arg);
	return 0;
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
  return 0;
}

