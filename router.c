#include "queue.h"
#include "skel.h"

#define MAX_LEN_RTABLE 1000000
#define MAX_LEN_ARP_TABLE 1000000

// routing table
struct route_table_entry *rtable;
int rtable_len;

// arp table
struct arp_entry *arp_table;
int arp_table_len;

// allocate memory for rtable and parse it
void get_rtable(const char *path) {
	rtable = malloc(MAX_LEN_RTABLE * sizeof(struct route_table_entry));
	DIE(!rtable, "malloc failed\n");

	rtable_len = read_rtable(path, rtable);
}

// allocate memory for arp_table
void create_arp_table() {
	arp_table = malloc(MAX_LEN_ARP_TABLE * sizeof(struct arp_entry));
	DIE(!arp_table, "malloc failed\n");
	arp_table_len = 0;
}

// adds a new enty to arp_table
void add_arp_entry(struct arp_entry new_entry) {
	arp_table_len++;
	arp_table[arp_table_len - 1] = new_entry;
}

// linear search to return arp entry with the given ip
struct arp_entry *find_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}

	// ip wasn't found in arp_table
	return NULL;
}

// function used to sort rtable
int compare_rtable_entries(const void *e1, const void *e2) {
	uint32_t e1_prefix = (*(struct route_table_entry *)e1).prefix;
	uint32_t e2_prefix = (*(struct route_table_entry *)e2).prefix;
	uint32_t e1_mask = (*(struct route_table_entry *)e1).mask;
	uint32_t e2_mask = (*(struct route_table_entry *)e2).mask;

	if ((e1_prefix & e1_mask) != (e2_prefix & e2_mask)) {
		// sort by masks if prefixes are equal
		return ntohl(e2_prefix & e2_mask) < ntohl(e1_prefix & e1_mask);
	} else {
		// sort by prefixes
		return ntohl(e2_mask) < ntohl(e1_mask);
	}
}


// binary search to get best route from rtable
struct route_table_entry *get_best_route(uint32_t dest_ip) {
	int left = 0, right = rtable_len - 1;
	int pos = -1;	// position of route with maximum mask

	while (left <= right) {
		int mid = left + (right - left) / 2;

		// check for match
		if ((rtable[mid].mask & dest_ip) == (rtable[mid].mask & rtable[mid].prefix)) {
			// save position and continue search for larger mask
			pos = mid;
			left = mid + 1;
		} else {
			if (ntohl(rtable[mid].mask & dest_ip) < ntohl(rtable[mid].mask & rtable[mid].prefix)) {
				right = mid - 1;
			} else {
				left = mid + 1;
			}
		}
	}

	if (pos != -1) {
		// return rtable entry
		return &rtable[pos];
	}
	// if no match was found
	return NULL;
}

void update_checksum(struct iphdr *ip_hdr) {
	uint16_t old_checksum = ip_hdr->check;
	// cast ttl value from uint8_t to uint16_t
	uint16_t old_ttl = (ip_hdr->ttl & 0xFFFF);

	// update ttl and recompute checksum
	--ip_hdr->ttl;
	uint16_t new_ttl = (ip_hdr->ttl & 0xFFFF);	
	ip_hdr->check = ~(~old_checksum + ~old_ttl + new_ttl) - 1;
}

// adds a new pachet to packets queue
void add_packet_to_queue(queue packets_queue,
							int interface, packet m) {

	packet *copy_packet = malloc(sizeof(packet));
	DIE(!copy_packet, "malloc failed\n");
	memcpy(copy_packet, &m, sizeof(packet));
	copy_packet->interface = interface;

	queue_enq(packets_queue, copy_packet);
}

// send packets with next_hop equal to arp packet source ip
void send_packets_from_queue(queue packets_queue, struct arp_header *arp_hdr) {
	queue unsend_packets_queue = queue_create();
	
	// check all packets from queue
	while(!queue_empty(packets_queue)) {
		// extract packet
		packet *curr_packet = (packet *)queue_deq(packets_queue);
		// extract ip header
		struct iphdr *ip_hdr_packet = (struct iphdr *)(curr_packet->payload + sizeof(struct ether_header));	

		// get best route for current packet
		struct route_table_entry *best_match = get_best_route(ip_hdr_packet->daddr);

		if (best_match->next_hop != arp_hdr->spa) {
			// add packet to unsend_packets_queue
			queue_enq(unsend_packets_queue, curr_packet);
		} else {
			// send packet	
			struct ether_header *eth_hdr_packet = (struct ether_header *)curr_packet->payload;
			memcpy(eth_hdr_packet->ether_dhost, arp_hdr->sha, ETH_ALEN);
			get_interface_mac(best_match->interface, eth_hdr_packet->ether_shost);

			curr_packet->interface = best_match->interface;

			send_packet(curr_packet);
		}
	}

	// move unsend packets to initial queue
	while (!queue_empty(unsend_packets_queue)) {
		// packet curr_packet = *(packet *)queue_deq(unsend_packets_queue);
		// queue_enq(packets_queue, &curr_packet);
		queue_enq(packets_queue, queue_deq(unsend_packets_queue));
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// initialise routing table and arp table
	get_rtable(argv[1]);
	create_arp_table();
	// create queue to store unsend packets
	queue packets_queue = queue_create();

	// sort routing table
	qsort(rtable, rtable_len, sizeof(struct route_table_entry), compare_rtable_entries);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */

		struct ether_header *eth_hdr = (struct ether_header *) m.payload;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			// extract arp_header from packet
			struct arp_header *arp_hdr = (struct arp_header *)(m.payload + sizeof(struct ether_header));

			if (ntohs(arp_hdr->op) == ARPOP_REQUEST) {
				// extract mac address from packet
				uint8_t mac_adr[ETH_ALEN];
				get_interface_mac(m.interface, mac_adr);

				// set eth_hdr
				memcpy(eth_hdr->ether_dhost, arp_hdr->sha, ETH_ALEN);
				memcpy(eth_hdr->ether_shost, mac_adr, ETH_ALEN);
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// send arp reply with my mac
				send_arp(arp_hdr->spa, arp_hdr->tpa, eth_hdr, m.interface, htons(ARPOP_REPLY));

				continue;
			}

			if (ntohs(arp_hdr->op) == ARPOP_REPLY) {
				// extract spa and sha from current packet and update arp_table
				// with new entry
				struct arp_entry new_entry;
				new_entry.ip = arp_hdr->spa;
				memcpy(new_entry.mac, arp_hdr->sha, ETH_ALEN);
				add_arp_entry(new_entry);

				// send packets with received mac from queue
				send_packets_from_queue(packets_queue, arp_hdr);

				continue;
			}
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			// extract ip header
			struct iphdr *ip_hdr = (struct iphdr *)(m.payload + sizeof(struct ether_header));

			// check if packet is for this router
			if (inet_addr(get_interface_ip(m.interface)) == ip_hdr->daddr) {
				if (ip_hdr->protocol == 1) {
					// received an icmp packet
					// extract icmp header
					struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + sizeof(struct ether_header) + sizeof(struct iphdr));

					if (icmp_hdr->type == ICMP_ECHO) {
						// send icmp
						send_icmp(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_ECHOREPLY, ICMP_ECHOREPLY, m.interface, icmp_hdr->un.echo.id, icmp_hdr->un.echo.sequence);
						continue;
					}
					continue;
				}
				continue;
			}

			if (ip_checksum((void *)ip_hdr, sizeof(struct iphdr))) {
				// drop packet
				continue;
			}

			if (ip_hdr->ttl <= 1) {
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_TIME_EXCEEDED, 0, m.interface);
				continue;
			}

			// if the packet is not for the router, find next hop
			struct route_table_entry *best_match = get_best_route(ip_hdr->daddr);

			if (!best_match) {
				// unreachable destination
				send_icmp_error(ip_hdr->saddr, ip_hdr->daddr, eth_hdr->ether_dhost, eth_hdr->ether_shost, ICMP_DEST_UNREACH, 0, m.interface);
				continue;
			}

			// update checksum after ttl decrementation
			update_checksum(ip_hdr);

			// find next_hop mac in the arp_table
			struct arp_entry *arp_entry_match = find_arp_entry(ip_hdr->daddr);

			if (arp_entry_match == NULL) {
				// enqueue packet
				add_packet_to_queue(packets_queue, best_match->interface, m);

				// daddr ip wasn't found in the arp_table
				// send arp request to get mac address of daddr ip
				uint8_t mac_addr[ETH_ALEN];
				get_interface_mac(best_match->interface, mac_addr);
				memcpy(eth_hdr->ether_shost, mac_addr, ETH_ALEN);
				// set eth_hdr->ether_dhost to broadcast address
				memset(eth_hdr->ether_dhost, 0xff, ETH_ALEN);
				// set packet type to arp
				eth_hdr->ether_type = htons(ETHERTYPE_ARP);

				// set source address
				uint32_t saddr = inet_addr(get_interface_ip(best_match->interface));

				// TODO: send arp request to get mac address of next hop
				send_arp(best_match->next_hop, saddr, eth_hdr, best_match->interface, htons(ARPOP_REQUEST));

				continue;
			} else {
				// forward packet
				get_interface_mac(best_match->interface, eth_hdr->ether_shost);
				memcpy(eth_hdr->ether_dhost, &arp_entry_match->mac, ETH_ALEN);

				m.interface = best_match->interface;

				send_packet(&m);

				continue;
			}
		}
	}
}
