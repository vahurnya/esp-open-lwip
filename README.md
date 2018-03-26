# Open lwIP with NAT, SLIP, and static routing for the ESP8266

## NAT
The new functions are exported in the "lwip/lwip_napt.h" header. NAPT should be enabled on the SoftAP interface of the ESP (this is typically the interface with netif.num == 1).

The additional NAPT functionality is enabled by the options IP_FORWARD, IP_NAPT, and IP_NAPT_DYNAMIC in "lwipopts.h".

This version of lwIP can replace the default version of lwIP in the esp-open-sdk. Just clone and replace the esp-lwip-open directory in the sdk.

It is based on neocat's NAPT extensions: https://github.com/NeoCat/esp8266-Arduino/commit/4108c8dbced7769c75bcbb9ed880f1d3f178bcbe

Fixes some issues I had with checksums and timers and can be used for full WiFi repeater functionality. If you want to use it as a permanent replacement for liblwib.a you might want to add the option IP_NAPT_DYNAMIC = 1. With this option the memory for the NAPT tables is allocated only, if ip_napt_init(max_nat, max_portmap) is called explicitly before enabling NAPT.

## SLIP
This stack also supports SLIP (Serial Line IP) interfaces via UARTs. To get this up and running, you will need an appropriate UART-driver and some initialization in the main program. You can find a demo at: https://github.com/martin-ger/esp_slip_router

## Static Routing Table

*experimental!*

IPv4 now has a static routing table. In "ip_route.h" there are these new functions:
```
struct route_entry {
    ip_addr_t ip;
    ip_addr_t mask;
    ip_addr_t gw;
};

/* Add a static route, true on success */
bool ip_add_route(ip_addr_t ip, ip_addr_t mask, ip_addr_t gw);

/* Remove a static route, true on success */
bool ip_rm_route(ip_addr_t ip, ip_addr_t mask);

/* Finds a route entry for an address, NULL if none */
struct route_entry *ip_find_route(ip_addr_t ip);

/* Delete all static routes */
void ip_delete_routes(void);

/* Returns the n_th entry of the routing table, true on success */
bool ip_get_route(uint32_t no, ip_addr_t *ip, ip_addr_t *mask, ip_addr_t *gw);
```

### Additional Netifs
- With LWIP_HAVE_LOOPIF 1 in lwipopts.h the stack configures a loopback interface at 127.0.0.1. To get it working either netif_poll_all() has to be called often in the main loop or the new global callback variable netif_loop_action has to be defined with a void* callback_fn(struct netif *netif) that schedules a netif_poll(netif) in the main task.

Added two additional preliminary netif implementations:
- The Ethernet ENC28J60 driver from https://github.com/Informatic/espenc . This should work with an ENC28J60 connected via SPI. To get this running,you will need at least this SPI driver: https://github.com/MetalPhreak/ESP8266_SPI_Driver . This is not yet tested.
- A TUNIF dummy device. This skeleton driver needs at least some additional load/unload functions to be useful for anything. It is intended as starting point for a tunnel device, e.g. for some kind of VPN tunnel.
