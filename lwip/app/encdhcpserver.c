#include "lwip/inet.h"
#include "lwip/err.h"
#include "lwip/pbuf.h"
#include "lwip/udp.h"
#include "lwip/mem.h"
#include "osapi.h"
#include "lwip/netif.h"
#include "lwip/netifapi.h"
#include "lwip/app/encdhcpserver.h"

#ifndef LWIP_OPEN_SRC
#include "net80211/ieee80211_var.h"
#endif

#include "user_interface.h"

#ifdef MEMLEAK_DEBUG
static const char mem_debug_file[] ICACHE_RODATA_ATTR = __FILE__;
#endif

////////////////////////////////////////////////////////////////////////////////////
static const uint32 magic_cookie ICACHE_RODATA_ATTR = 0x63538263;
static struct udp_pcb *enc_pcb_dhcps = NULL;
static struct ip_addr enc_broadcast_dhcps;
static struct ip_addr enc_server_address;
static struct ip_addr enc_client_address; //added
static struct ip_addr enc_client_address_plus;

static struct ip_addr enc_dns_address = {0};

static struct dhcps_lease enc_dhcps_lease;
static list_node *enc_plist = NULL;
static uint8 enc_offer = 0xFF;
static bool enc_renew = false;
#define DHCPS_LEASE_TIME_DEF	(120)
uint32 enc_dhcps_lease_time = DHCPS_LEASE_TIME_DEF; //minute
static struct netif ecnetif;
static bool enc_dhcp_server_running = false;

// Steal functions from dhcp server used on wifi...
// THESE WILL GROW WITH TIME AND SHOULD BE A SEPARATE C AND H FILE
extern void node_insert_to_list(list_node **phead, list_node* pinsert);
extern void node_remove_from_list(list_node **phead, list_node* pdelete);
//extern uint8_t* ICACHE_FLASH_ATTR add_msg_type(uint8_t *optptr, uint8_t type);
//extern uint8_t* ICACHE_FLASH_ATTR add_end(uint8_t *optptr);

// many more can be stolen, eventually.
static uint8_t* ICACHE_FLASH_ATTR add_msg_type(uint8_t *optptr, uint8_t type) {

        *optptr++ = DHCP_OPTION_MSG_TYPE;
        *optptr++ = 1;
        *optptr++ = type;
        return optptr;
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ��DHCP msg�ṹ����ӽ����־����
 *
 * @param optptr -- DHCP msg��Ϣλ��
 *
 * @return uint8_t* ����DHCP msgƫ�Ƶ�ַ
 */
///////////////////////////////////////////////////////////////////////////////////

static uint8_t* ICACHE_FLASH_ATTR add_end(uint8_t *optptr) {

        *optptr++ = DHCP_OPTION_END;
        return optptr;
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ��DHCP msg�ṹ������offerӦ������
 *
 * @param optptr -- DHCP msg��Ϣλ��
 *
 * @return uint8_t* ����DHCP msgƫ�Ƶ�ַ
 */
///////////////////////////////////////////////////////////////////////////////////

static uint8_t* ICACHE_FLASH_ATTR enc_add_offer_options(uint8_t *optptr) {
        struct ip_addr ipadd;

        ipadd.addr = *((uint32_t *) & enc_server_address);

#ifdef USE_CLASS_B_NET
        *optptr++ = DHCP_OPTION_SUBNET_MASK;
        *optptr++ = 4; //length
        *optptr++ = 255;
        *optptr++ = 240;
        *optptr++ = 0;
        *optptr++ = 0;
#else
        *optptr++ = DHCP_OPTION_SUBNET_MASK;
        *optptr++ = 4;
        *optptr++ = 255;
        *optptr++ = 255;
        *optptr++ = 255;
        *optptr++ = 0;
#endif

        *optptr++ = DHCP_OPTION_LEASE_TIME;
        *optptr++ = 4;
        *optptr++ = ((enc_DHCPS_LEASE_TIMER * 60) >> 24) & 0xFF;
        *optptr++ = ((enc_DHCPS_LEASE_TIMER * 60) >> 16) & 0xFF;
        *optptr++ = ((enc_DHCPS_LEASE_TIMER * 60) >> 8) & 0xFF;
        *optptr++ = ((enc_DHCPS_LEASE_TIMER * 60) >> 0) & 0xFF;

        *optptr++ = DHCP_OPTION_SERVER_ID;
        *optptr++ = 4;
        *optptr++ = ip4_addr1(&ipadd);
        *optptr++ = ip4_addr2(&ipadd);
        *optptr++ = ip4_addr3(&ipadd);
        *optptr++ = ip4_addr4(&ipadd);

        if(enc_dhcps_router_enabled(enc_offer)) {
                struct ip_info if_ip;

                if_ip.gw = enc_server_address;
#if ENCDHCPS_DEBUG
        os_printf("encdhcp: send gw address %"U16_F".%"U16_F".%"U16_F".%"U16_F"\n", ip4_addr1_16(&if_ip.gw), ip4_addr2_16(&if_ip.gw), ip4_addr3_16(&if_ip.gw), ip4_addr4_16(&if_ip.gw));
#endif

                *optptr++ = DHCP_OPTION_ROUTER;
                *optptr++ = 4;
                *optptr++ = ip4_addr1(&if_ip.gw);
                *optptr++ = ip4_addr2(&if_ip.gw);
                *optptr++ = ip4_addr3(&if_ip.gw);
                *optptr++ = ip4_addr4(&if_ip.gw);
        }

#ifdef USE_DNS
        *optptr++ = DHCP_OPTION_DNS_SERVER;
        *optptr++ = 4;
        *optptr++ = ip4_addr1(&enc_dns_address);
        *optptr++ = ip4_addr2(&enc_dns_address);
        *optptr++ = ip4_addr3(&enc_dns_address);
        *optptr++ = ip4_addr4(&enc_dns_address);
#endif

#ifdef CLASS_B_NET
        *optptr++ = DHCP_OPTION_BROADCAST_ADDRESS;
        *optptr++ = 4;
        *optptr++ = ip4_addr1(&ipadd);
        *optptr++ = 255;
        *optptr++ = 255;
        *optptr++ = 255;
#else
        *optptr++ = DHCP_OPTION_BROADCAST_ADDRESS;
        *optptr++ = 4;
        *optptr++ = ip4_addr1(&ipadd);
        *optptr++ = ip4_addr2(&ipadd);
        *optptr++ = ip4_addr3(&ipadd);
        *optptr++ = 255;
#endif

        *optptr++ = DHCP_OPTION_INTERFACE_MTU;
        *optptr++ = 2;
#ifdef CLASS_B_NET
        *optptr++ = 0x05;
        *optptr++ = 0xdc;
#else
        *optptr++ = 0x02;
        *optptr++ = 0x40;
#endif

        *optptr++ = DHCP_OPTION_PERFORM_ROUTER_DISCOVERY;
        *optptr++ = 1;
        *optptr++ = 0x00;

        *optptr++ = 43;
        *optptr++ = 6;

        *optptr++ = 0x01;
        *optptr++ = 4;
        *optptr++ = 0x00;
        *optptr++ = 0x00;
        *optptr++ = 0x00;
        *optptr++ = 0x02;

        return optptr;
}
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_create_msg(struct dhcps_msg *m) {
        struct ip_addr client;

        client.addr = *((uint32_t *) & enc_client_address);

        m->op = DHCP_REPLY;
        m->htype = DHCP_HTYPE_ETHERNET;
        m->hlen = 6;
        m->hops = 0;
        //        os_memcpy((char *) xid, (char *) m->xid, sizeof(m->xid));
        m->secs = 0;
        m->flags = htons(BOOTP_BROADCAST);

        os_memcpy((char *) m->yiaddr, (char *) &client.addr, sizeof(m->yiaddr));

        os_memset((char *) m->ciaddr, 0, sizeof(m->ciaddr));
        os_memset((char *) m->siaddr, 0, sizeof(m->siaddr));
        os_memset((char *) m->giaddr, 0, sizeof(m->giaddr));
        os_memset((char *) m->sname, 0, sizeof(m->sname));
        os_memset((char *) m->file, 0, sizeof(m->file));

        os_memset((char *) m->options, 0, sizeof(m->options));
        os_memcpy((char *) m->options, &magic_cookie, sizeof(magic_cookie));
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ����һ��OFFER
 *
 * @param -- m ָ����Ҫ���͵�DHCP msg����
 */
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_send_offer(struct dhcps_msg *m) {
        uint8_t *end;
        struct pbuf *p, *q;
        u8_t *data;
        u16_t cnt = 0;
        u16_t i;
        err_t SendOffer_err_t;
        enc_create_msg(m);

        end = add_msg_type(&m->options[4], DHCPOFFER);
        end = enc_add_offer_options(end);
        end = add_end(end);

        p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcps_msg), PBUF_RAM);
#if ENCDHCPS_DEBUG
        os_printf("encdhcp: send_offer>>p->ref = %d\n", p->ref);
#endif
        if(p != NULL) {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_offer>>pbuf_alloc succeed\n");
                os_printf("encdhcps: send_offer>>p->tot_len = %d\n", p->tot_len);
                os_printf("encdhcps: send_offer>>p->len = %d\n", p->len);
#endif
                q = p;
                while(q != NULL) {
                        data = (u8_t *) q->payload;
                        for(i = 0; i < q->len; i++) {
                                data[i] = ((u8_t *) m)[cnt++];
#if ENCDHCPS_DEBUG
                                os_printf("%02x ", data[i]);
                                if((i + 1) % 16 == 0) {
                                        os_printf("\n");
                                }
#endif
                        }

                        q = q->next;
                }
        } else {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_offer>>pbuf_alloc failed\n");
#endif
                return;
        }
        SendOffer_err_t = udp_sendto(enc_pcb_dhcps, p, &enc_broadcast_dhcps, DHCPS_CLIENT_PORT);
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: send_offer>>udp_sendto result %x\n", SendOffer_err_t);
#endif
        if(p->ref != 0) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcp: send_offer>>free pbuf\n");
#endif
                pbuf_free(p);
        }
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ����һ��NAK��Ϣ
 *
 * @param m ָ����Ҫ���͵�DHCP msg����
 */
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_send_nak(struct dhcps_msg *m) {

        u8_t *end;
        struct pbuf *p, *q;
        u8_t *data;
        u16_t cnt = 0;
        u16_t i;
        err_t SendNak_err_t;
        enc_create_msg(m);

        end = add_msg_type(&m->options[4], DHCPNAK);
        end = add_end(end);

        p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcps_msg), PBUF_RAM);
#if ENCDHCPS_DEBUG
        os_printf("encdhcp: send_nak>>p->ref = %d\n", p->ref);
#endif
        if(p != NULL) {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_nak>>pbuf_alloc succeed\n");
                os_printf("encdhcps: send_nak>>p->tot_len = %d\n", p->tot_len);
                os_printf("encdhcps: send_nak>>p->len = %d\n", p->len);
#endif
                q = p;
                while(q != NULL) {
                        data = (u8_t *) q->payload;
                        for(i = 0; i < q->len; i++) {
                                data[i] = ((u8_t *) m)[cnt++];
#if ENCDHCPS_DEBUG
                                os_printf("%02x ", data[i]);
                                if((i + 1) % 16 == 0) {
                                        os_printf("\n");
                                }
#endif
                        }

                        q = q->next;
                }
        } else {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_nak>>pbuf_alloc failed\n");
#endif
                return;
        }
        SendNak_err_t = udp_sendto(enc_pcb_dhcps, p, &enc_broadcast_dhcps, DHCPS_CLIENT_PORT);
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: send_nak>>udp_sendto result %x\n", SendNak_err_t);
#endif
        if(p->ref != 0) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcp: send_nak>>free pbuf\n");
#endif
                pbuf_free(p);
        }
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ����һ��ACK��DHCP�ͻ���
 *
 * @param m ָ����Ҫ���͵�DHCP msg����
 */
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_send_ack(struct dhcps_msg *m) {

        u8_t *end;
        struct pbuf *p, *q;
        u8_t *data;
        u16_t cnt = 0;
        u16_t i;
        err_t SendAck_err_t;
        enc_create_msg(m);

        end = add_msg_type(&m->options[4], DHCPACK);
        end = enc_add_offer_options(end);
        end = add_end(end);

        p = pbuf_alloc(PBUF_TRANSPORT, sizeof(struct dhcps_msg), PBUF_RAM);
#if ENCDHCPS_DEBUG
        os_printf("encdhcp: send_ack>>p->ref = %d\n", p->ref);
#endif
        if(p != NULL) {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_ack>>pbuf_alloc succeed\n");
                os_printf("encdhcps: send_ack>>p->tot_len = %d\n", p->tot_len);
                os_printf("encdhcps: send_ack>>p->len = %d\n", p->len);
#endif
                q = p;
                while(q != NULL) {
                        data = (u8_t *) q->payload;
                        for(i = 0; i < q->len; i++) {
                                data[i] = ((u8_t *) m)[cnt++];
#if ENCDHCPS_DEBUG
                                os_printf("%02x ", data[i]);
                                if((i + 1) % 16 == 0) {
                                        os_printf("\n");
                                }
#endif
                        }

                        q = q->next;
                }
        } else {

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: send_ack>>pbuf_alloc failed\n");
#endif
                return;
        }
        SendAck_err_t = udp_sendto(enc_pcb_dhcps, p, &enc_broadcast_dhcps, DHCPS_CLIENT_PORT);
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: send_ack>>udp_sendto result %x\n", SendAck_err_t);
#endif

        if(p->ref != 0) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcp: send_ack>>free pbuf\n");
#endif
                pbuf_free(p);
        }
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * ����DHCP�ͻ��˷�����DHCP����������Ϣ�����Բ�ͬ��DHCP��������������Ӧ��Ӧ��
 *
 * @param optptr DHCP msg�е���������
 * @param len ��������Ĵ��?(byte)
 *
 * @return uint8_t ���ش�����DHCP Server״ֵ̬
 */
///////////////////////////////////////////////////////////////////////////////////

static uint8_t ICACHE_FLASH_ATTR enc_parse_options(uint8_t *optptr, sint16_t len) {
        struct ip_addr client;
        bool is_dhcp_parse_end = false;
        struct dhcps_state s;

        client.addr = *((uint32_t *) & enc_client_address); // Ҫ�����DHCP�ͻ��˵�IP

        u8_t *end = optptr + len;
        u16_t type = 0;

        s.state = DHCPS_STATE_IDLE;

        while(optptr < end) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcps: (sint16_t)*optptr = %d\n", (sint16_t) * optptr);
#endif
                switch((sint16_t) * optptr) {

                        case DHCP_OPTION_MSG_TYPE: //53
                                type = *(optptr + 2);
                                break;

                        case DHCP_OPTION_REQ_IPADDR://50
                                if(os_memcmp((char *) &client.addr, (char *) optptr + 2, 4) == 0) {
#if ENCDHCPS_DEBUG
                                        os_printf("encdhcps: DHCP_OPTION_REQ_IPADDR = 0 ok\n");
#endif
                                        s.state = DHCPS_STATE_ACK;
                                } else {
#if ENCDHCPS_DEBUG
                                        os_printf("encdhcps: DHCP_OPTION_REQ_IPADDR != 0 err\n");
#endif
                                        s.state = DHCPS_STATE_NAK;
                                }
                                break;
                        case DHCP_OPTION_END:
                        {
                                is_dhcp_parse_end = true;
                        }
                                break;
                }

                if(is_dhcp_parse_end) {
                        break;
                }

                optptr += optptr[1] + 2;
        }

        switch(type) {

                case DHCPDISCOVER://1
                        s.state = DHCPS_STATE_OFFER;
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: DHCPD_STATE_OFFER\n");
#endif
                        break;

                case DHCPREQUEST://3
                        if(!(s.state == DHCPS_STATE_ACK || s.state == DHCPS_STATE_NAK)) {
                                if(enc_renew == true) {
                                        s.state = DHCPS_STATE_ACK;
                                } else {
                                        s.state = DHCPS_STATE_NAK;
                                }
#if ENCDHCPS_DEBUG
                                os_printf("encdhcps: DHCPD_STATE_NAK\n");
#endif
                        }
                        break;

                case DHCPDECLINE://4
                        s.state = DHCPS_STATE_IDLE;
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: DHCPD_STATE_IDLE\n");
#endif
                        break;

                case DHCPRELEASE://7
                        s.state = DHCPS_STATE_RELEASE;
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: DHCPD_STATE_IDLE\n");
#endif
                        break;
        }
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: return s.state = %d\n", s.state);
#endif
        return s.state;
}
///////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////////////////////////////////////////////////

static sint16_t ICACHE_FLASH_ATTR enc_parse_msg(struct dhcps_msg *m, u16_t len) {
        if(os_memcmp((char *) m->options,
                &magic_cookie,
                sizeof(magic_cookie)) == 0) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcps: len = %d\n", len);
#endif
                /*
                 * ��¼���ε�xid�ţ�ͬʱ�����IP����
                 */
                struct ip_addr addr_tmp;
                struct dhcps_pool *pdhcps_pool = NULL;
                list_node *pnode = NULL;
                list_node *pback_node = NULL;
                struct ip_addr first_address;
                bool flag = false;

                first_address.addr = enc_dhcps_lease.start_ip.addr;
                enc_client_address.addr = enc_client_address_plus.addr;
                enc_renew = false;
                for(pback_node = enc_plist; pback_node != NULL; pback_node = pback_node->pnext) {
                        pdhcps_pool = pback_node->pnode;
                        if(os_memcmp(pdhcps_pool->mac, m->chaddr, sizeof(pdhcps_pool->mac)) == 0) {
                                //      os_printf("the same device request ip\n");
                                if(os_memcmp(&pdhcps_pool->ip.addr, m->ciaddr, sizeof(pdhcps_pool->ip.addr)) == 0) {
                                        enc_renew = true;
                                }
                                enc_client_address.addr = pdhcps_pool->ip.addr;
                                pdhcps_pool->lease_timer = enc_DHCPS_LEASE_TIMER;
                                pnode = pback_node;
                                goto POOL_CHECK;
                        } else if(pdhcps_pool->ip.addr == enc_client_address_plus.addr) {
                                addr_tmp.addr = htonl(enc_client_address_plus.addr);
                                addr_tmp.addr++;
                                enc_client_address_plus.addr = htonl(addr_tmp.addr);
                                enc_client_address.addr = enc_client_address_plus.addr;
                        }

                        if(flag == false) { // search the first unused ip
                                if(first_address.addr < pdhcps_pool->ip.addr) {
                                        flag = true;
                                } else {
                                        addr_tmp.addr = htonl(first_address.addr);
                                        addr_tmp.addr++;
                                        first_address.addr = htonl(addr_tmp.addr);
                                }
                        }
                }
                if(enc_client_address_plus.addr > enc_dhcps_lease.end_ip.addr) {
                        enc_client_address.addr = first_address.addr;
                }
                if(enc_client_address.addr > enc_dhcps_lease.end_ip.addr) {
                        enc_client_address_plus.addr = enc_dhcps_lease.start_ip.addr;
                        pdhcps_pool = NULL;
                        pnode = NULL;
                } else {
                        pdhcps_pool = (struct dhcps_pool *) os_zalloc(sizeof(struct dhcps_pool));
                        pdhcps_pool->ip.addr = enc_client_address.addr;
                        os_memcpy(pdhcps_pool->mac, m->chaddr, sizeof(pdhcps_pool->mac));
                        pdhcps_pool->lease_timer = enc_DHCPS_LEASE_TIMER;
                        pnode = (list_node *) os_zalloc(sizeof(list_node));
                        pnode->pnode = pdhcps_pool;
                        pnode->pnext = NULL;
                        node_insert_to_list(&enc_plist, pnode);
                        if(enc_client_address.addr == enc_dhcps_lease.end_ip.addr) {
                                enc_client_address_plus.addr = enc_dhcps_lease.start_ip.addr;
                        } else {
                                addr_tmp.addr = htonl(enc_client_address.addr);
                                addr_tmp.addr++;
                                enc_client_address_plus.addr = htonl(addr_tmp.addr);
                        }
                }

POOL_CHECK:
                if((enc_client_address.addr > enc_dhcps_lease.end_ip.addr) || (ip_addr_isany(&enc_client_address))) {
                        //      os_printf("encdhcp: client_address_plus.addr %x %d\n", enc_client_address_plus.addr, system_get_free_heap_size());
                        if(pnode != NULL) {
                                node_remove_from_list(&enc_plist, pnode);
                                os_free(pnode);
                                pnode = NULL;
                        }

                        if(pdhcps_pool != NULL) {
                                os_free(pdhcps_pool);
                                pdhcps_pool = NULL;
                        }
                        //	client_address_plus.addr = dhcps_lease.start_ip.addr;
                        return 4;
                }

                sint16_t ret = enc_parse_options(&m->options[4], len);

                if(ret == DHCPS_STATE_RELEASE) {
                        if(pnode != NULL) {
                                node_remove_from_list(&enc_plist, pnode);
                                os_free(pnode);
                                pnode = NULL;
                        }

                        if(pdhcps_pool != NULL) {
                                os_free(pdhcps_pool);
                                pdhcps_pool = NULL;
                        }
                        os_memset(&enc_client_address, 0x0, sizeof(enc_client_address));
                }

#if ENCDHCPS_DEBUG
                os_printf("encdhcps: xid changed\n");
                os_printf("encdhcps: client_address.addr = %x\n", enc_client_address.addr);
#endif

                return ret;
        }
        return 0;
}
///////////////////////////////////////////////////////////////////////////////////
/*
 * DHCP ��������ݰ���մ���ص�����˺�����LWIP UDPģ������ʱ������
 * ��Ҫ����udp_recv()������LWIP����ע��.
 *
 * @param arg
 * @param pcb ���յ�UDP��Ŀ��ƿ�?
 * @param p ���յ���UDP�е��������?
 * @param addr ���ʹ�UDP���Դ�����IP��ַ
 * @param port ���ʹ�UDP���Դ�����UDPͨ���˿ں�
 */
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_handle_dhcp(void *arg,
        struct udp_pcb *pcb,
        struct pbuf *p,
        struct ip_addr *addr,
        uint16_t port) {
        struct dhcps_msg *pmsg_dhcps = NULL;
        sint16_t tlen = 0;
        u16_t i = 0;
        u16_t dhcps_msg_cnt = 0;
        u8_t *p_dhcps_msg = NULL;
        u8_t *data = NULL;

#if ENCDHCPS_DEBUG
        os_printf("encdhcps: handle_dhcp-> receive a packet\n");
#endif
        if(p == NULL) return;

        pmsg_dhcps = (struct dhcps_msg *) os_zalloc(sizeof(struct dhcps_msg));
        if(NULL == pmsg_dhcps) {
                pbuf_free(p);
                return;
        }
        p_dhcps_msg = (u8_t *) pmsg_dhcps;
        tlen = p->tot_len;
        data = p->payload;

#if ENCDHCPS_DEBUG
        os_printf("encdhcps: handle_dhcp-> p->tot_len = %d\n", tlen);
        os_printf("encdhcps: handle_dhcp-> p->len = %d\n", p->len);
#endif

        for(i = 0; i < p->len; i++) {
                p_dhcps_msg[dhcps_msg_cnt++] = data[i];
#if ENCDHCPS_DEBUG
                os_printf("%02x ", data[i]);
                if((i + 1) % 16 == 0) {
                        os_printf("\n");
                }
#endif
        }

        if(p->next != NULL) {
#if ENCDHCPS_DEBUG
                os_printf("encdhcps: handle_dhcp-> p->next != NULL\n");
                os_printf("encdhcps: handle_dhcp-> p->next->tot_len = %d\n", p->next->tot_len);
                os_printf("encdhcps: handle_dhcp-> p->next->len = %d\n", p->next->len);
#endif

                data = p->next->payload;
                for(i = 0; i < p->next->len; i++) {
                        p_dhcps_msg[dhcps_msg_cnt++] = data[i];
#if ENCDHCPS_DEBUG
                        os_printf("%02x ", data[i]);
                        if((i + 1) % 16 == 0) {
                                os_printf("\n");
                        }
#endif
                }
        }

        /*
         * DHCP �ͻ���������Ϣ����
         */
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: handle_dhcp-> parse_msg(p)\n");
#endif

        switch(enc_parse_msg(pmsg_dhcps, tlen - 240)) {

                case DHCPS_STATE_OFFER://1
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: handle_dhcp-> DHCPD_STATE_OFFER\n");
#endif
                        enc_send_offer(pmsg_dhcps);
                        break;
                case DHCPS_STATE_ACK://3
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: handle_dhcp-> DHCPD_STATE_ACK\n");
#endif
                        enc_send_ack(pmsg_dhcps);
                        break;
                case DHCPS_STATE_NAK://4
#if ENCDHCPS_DEBUG
                        os_printf("encdhcps: handle_dhcp-> DHCPD_STATE_NAK\n");
#endif
                        enc_send_nak(pmsg_dhcps);
                        break;
                default:
                        break;
        }
#if ENCDHCPS_DEBUG
        os_printf("encdhcps: handle_dhcp-> pbuf_free(p)\n");
#endif
        pbuf_free(p);
        os_free(pmsg_dhcps);
        pmsg_dhcps = NULL;
}
///////////////////////////////////////////////////////////////////////////////////

static void ICACHE_FLASH_ATTR enc_softap_init_dhcps_lease(uint32 ip) {
        uint32 softap_ip = 0, local_ip = 0;
        uint32 start_ip = 0;
        uint32 end_ip = 0;
        if(enc_dhcps_lease.enable == TRUE) {
                softap_ip = htonl(ip);
                start_ip = htonl(enc_dhcps_lease.start_ip.addr);
                end_ip = htonl(enc_dhcps_lease.end_ip.addr);
                /*config ip information can't contain local ip*/
                if((start_ip <= softap_ip) && (softap_ip <= end_ip)) {
                        enc_dhcps_lease.enable = FALSE;
                } else {
                        /*config ip information must be in the same segment as the local ip*/
                        softap_ip >>= 8;
                        if(((start_ip >> 8 != softap_ip) || (end_ip >> 8 != softap_ip))
                                || (end_ip - start_ip > DHCPS_MAX_LEASE)) {
                                enc_dhcps_lease.enable = FALSE;
                        }
                }
        }

        if(enc_dhcps_lease.enable == FALSE) {
                local_ip = softap_ip = htonl(ip);
                softap_ip &= 0xFFFFFF00;
                local_ip &= 0xFF;
                if(local_ip >= 0x80)
                        local_ip -= DHCPS_MAX_LEASE;
                else
                        local_ip++;

                os_bzero(&enc_dhcps_lease, sizeof(enc_dhcps_lease));
                enc_dhcps_lease.start_ip.addr = softap_ip | local_ip;
                enc_dhcps_lease.end_ip.addr = softap_ip | (local_ip + DHCPS_MAX_LEASE - 1);
                enc_dhcps_lease.start_ip.addr = htonl(enc_dhcps_lease.start_ip.addr);
                enc_dhcps_lease.end_ip.addr = htonl(enc_dhcps_lease.end_ip.addr);
        }
        //	os_printf("start_ip = 0x%x, end_ip = 0x%x\n",dhcps_lease.start_ip, dhcps_lease.end_ip);
}
///////////////////////////////////////////////////////////////////////////////////

void ICACHE_FLASH_ATTR enc_dhcps_start(struct netif* enetif) {

        if(enetif == NULL) {
                // os_printf("encdhcps: dhcps_start(): enetif == NULL\n");
                return;
        }
        if(enetif->dhcps_pcb != NULL) {
                udp_remove(enetif->dhcps_pcb);
        }

        enc_pcb_dhcps = udp_new();
        if(enc_pcb_dhcps == NULL) {
                // os_printf("encdhcps: dhcps_start(): could not obtain pcb\n");
                return;
        }

        enetif->dhcps_pcb = enc_pcb_dhcps;

        IP4_ADDR(&enc_broadcast_dhcps, 255, 255, 255, 255);

        enc_server_address = enetif->ip_addr;
        if(enc_dns_address.addr == 0) {
                enc_dns_address = enc_server_address;
        }

        enc_softap_init_dhcps_lease(enc_server_address.addr);
        enc_client_address_plus.addr = enc_dhcps_lease.start_ip.addr;

        udp_bind(enc_pcb_dhcps, &enetif->ip_addr, DHCPS_SERVER_PORT);
        udp_recv(enc_pcb_dhcps, enc_handle_dhcp, NULL);
#if ENCDHCPS_DEBUG
        os_printf("encdhcps:dhcps_start->udp_recv function Set a receive callback handle_dhcp for UDP_PCB pcb_dhcps\n");
#endif
        enc_dhcp_server_running = true;
}

void ICACHE_FLASH_ATTR enc_dhcps_stop(void) {

        enc_dhcp_server_running = false;
        udp_disconnect(enc_pcb_dhcps);
        if(ecnetif.dhcps_pcb != NULL) {
                udp_remove(ecnetif.dhcps_pcb);
                ecnetif.dhcps_pcb = NULL;
        }


        list_node *pnode = NULL;
        list_node *pback_node = NULL;
        pnode = enc_plist;
        while(pnode != NULL) {
                pback_node = pnode;
                pnode = pback_node->pnext;
                node_remove_from_list(&enc_plist, pback_node);
                os_free(pback_node->pnode);
                pback_node->pnode = NULL;
                os_free(pback_node);
                pback_node = NULL;
        }
}

/******************************************************************************
 * FunctionName : enc_softap_set_dhcps_lease
 * Description  : set the lease information of DHCP server
 * Parameters   : please -- Additional argument to set the lease information,
 * 							Little-Endian.
 * Returns      : true or false
 *******************************************************************************/
bool ICACHE_FLASH_ATTR enc_softap_set_dhcps_lease(struct dhcps_lease *please) {
        uint32 softap_ip = 0;
        uint32 start_ip = 0;
        uint32 end_ip = 0;

        if(please == NULL || enc_dhcp_server_running)
                return false;

        if(please->enable) {
                softap_ip = htonl(ecnetif.ip_addr.addr);
                start_ip = htonl(please->start_ip.addr);
                end_ip = htonl(please->end_ip.addr);

                /*config ip information can't contain local ip*/
                if((start_ip <= softap_ip) && (softap_ip <= end_ip))
                        return false;

                /*config ip information must be in the same segment as the local ip*/
                softap_ip >>= 8;
                if((start_ip >> 8 != softap_ip)
                        || (end_ip >> 8 != softap_ip)) {
                        return false;
                }

                if(end_ip - start_ip > DHCPS_MAX_LEASE)
                        return false;

                os_bzero(&enc_dhcps_lease, sizeof(enc_dhcps_lease));
                enc_dhcps_lease.start_ip.addr = please->start_ip.addr;
                enc_dhcps_lease.end_ip.addr = please->end_ip.addr;
        }
        enc_dhcps_lease.enable = please->enable;
        return true;
}

/******************************************************************************
 * FunctionName : enc_softap_get_dhcps_lease
 * Description  : get the lease information of DHCP server
 * Parameters   : please -- Additional argument to get the lease information,
 * 							Little-Endian.
 * Returns      : true or false
 *******************************************************************************/
bool ICACHE_FLASH_ATTR enc_softap_get_dhcps_lease(struct dhcps_lease *please) {
        if(NULL == please)
                return false;

        if(enc_dhcps_lease.enable == FALSE) {
                if(!enc_dhcp_server_running)
                        return false;
        }

        please->start_ip.addr = enc_dhcps_lease.start_ip.addr;
        please->end_ip.addr = enc_dhcps_lease.end_ip.addr;
        return true;
}

static void ICACHE_FLASH_ATTR enc_kill_oldest_dhcps_pool(void) {
        list_node *pre = NULL, *p = NULL;
        list_node *minpre = NULL, *minp = NULL;
        struct dhcps_pool *pdhcps_pool = NULL, *pmin_pool = NULL;
        pre = enc_plist;
        p = pre->pnext;
        minpre = pre;
        minp = p;
        while(p != NULL) {
                pdhcps_pool = p->pnode;
                pmin_pool = minp->pnode;
                if(pdhcps_pool->lease_timer < pmin_pool->lease_timer) {
                        minp = p;
                        minpre = pre;
                }
                pre = p;
                p = p->pnext;
        }
        minpre->pnext = minp->pnext;
        os_free(minp->pnode);
        minp->pnode = NULL;
        os_free(minp);
        minp = NULL;
}

void ICACHE_FLASH_ATTR enc_dhcps_coarse_tmr(void) {
        uint8 num_dhcps_pool = 0;
        list_node *pback_node = NULL;
        list_node *pnode = NULL;
        struct dhcps_pool *pdhcps_pool = NULL;
        pnode = enc_plist;
        while(pnode != NULL) {
                pdhcps_pool = pnode->pnode;
                pdhcps_pool->lease_timer--;
                if(pdhcps_pool->lease_timer == 0) {
                        pback_node = pnode;
                        pnode = pback_node->pnext;
                        node_remove_from_list(&enc_plist, pback_node);
                        os_free(pback_node->pnode);
                        pback_node->pnode = NULL;
                        os_free(pback_node);
                        pback_node = NULL;
                } else {
                        pnode = pnode ->pnext;
                        num_dhcps_pool++;
                }
        }

        if(num_dhcps_pool >= MAX_STATION_NUM)
                enc_kill_oldest_dhcps_pool();
}

bool ICACHE_FLASH_ATTR enc_softap_set_dhcps_offer_option(uint8 level, void* optarg) {
        bool offer_flag = true;
        uint8 option = 0;

        if(optarg == NULL && !enc_dhcp_server_running)
                return false;

        if(level <= OFFER_START || level >= OFFER_END)
                return false;

        switch(level) {
                case OFFER_ROUTER:
                        enc_offer = (*(uint8 *) optarg) & 0x01;
                        offer_flag = true;
                        break;
                default:
                        offer_flag = false;
                        break;
        }
        return offer_flag;
}

bool ICACHE_FLASH_ATTR enc_softap_set_dhcps_lease_time(uint32 minute) {

        if(enc_dhcp_server_running) {
                return false;
        }

        if(minute == 0) {
                return false;
        }
        enc_dhcps_lease_time = minute;
        return true;
}

bool ICACHE_FLASH_ATTR enc_softap_reset_dhcps_lease_time(void) {

        if(enc_dhcp_server_running) {
                return false;
        }
        enc_dhcps_lease_time = DHCPS_LEASE_TIME_DEF;
        return true;
}

uint32 ICACHE_FLASH_ATTR enc_softap_get_dhcps_lease_time(void) // minute
{
        return enc_dhcps_lease_time;
}

void ICACHE_FLASH_ATTR enc_dhcps_set_DNS(struct ip_addr *dns_ip) {
        enc_dns_address = *dns_ip;
}

struct dhcps_pool *ICACHE_FLASH_ATTR enc_dhcps_get_mapping(uint16_t no) {
        list_node *pback_node = NULL;

        for(pback_node = enc_plist; pback_node != NULL; pback_node = pback_node->pnext, no--) {
                if(no == 0) return pback_node->pnode;
        }
        return NULL;
}

void ICACHE_FLASH_ATTR enc_dhcps_set_mapping(struct ip_addr *addr, uint8 *mac, uint32 lease_time) {
        list_node *pback_node = NULL;
        list_node *pnode = NULL;
        struct dhcps_pool *pdhcps_pool = NULL;

        pdhcps_pool = (struct dhcps_pool *) os_zalloc(sizeof(struct dhcps_pool));
        pdhcps_pool->ip.addr = addr->addr;
        os_memcpy(pdhcps_pool->mac, mac, sizeof(pdhcps_pool->mac));
        pdhcps_pool->lease_timer = lease_time;
        pnode = (list_node *) os_zalloc(sizeof(list_node));
        pnode->pnode = pdhcps_pool;
        pnode->pnext = NULL;
        node_insert_to_list(&enc_plist, pnode);
}
