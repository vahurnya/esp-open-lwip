#ifndef __LWIP_IP_ROUTE_H__
#define __LWIP_IP_ROUTE_H__

#include "lwip/opt.h"
#include "lwip/ip_addr.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef IP_ROUTING_TAB
/* Add a static route as top entry */
bool ip_add_route(ip_addr_t ip, ip_addr_t mask, ip_addr_t gw);

/* Removes a static route entry */
bool ip_rm_route(ip_addr_t ip, ip_addr_t mask);

/* Delete all static routes */
void ip_delete_routes(void);
#endif /* IP_ROUTING_TAB */

#ifdef __cplusplus
}
#endif

#endif /* __LWIP_IP_ROUTE_H__ */
