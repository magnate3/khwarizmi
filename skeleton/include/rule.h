struct rule {
	uint32_t src_ip;
	uint32_t dest_ip;
	uint8_t proto;
	uint16_t th_sport;
	uint16_t th_dport;
};

void list_init(void);
