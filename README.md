# Open lwIP with NAT for the esp8266

The new functions are exported in the "lwip/lwip_napt.h" header. NAPT should be enabled on the SoftAP interface of the ESP (this is typically the interface with netif.num == 1).

The additional NAPT functionality is enabled by the options IP_FORWARD, IP_NAPT, and IP_NAPT_DYNAMIC in "lwipopts.h".

This version of lwIP can replace the default version of lwIP in the esp-open-sdk. Just clone and replace the esp-lwip-open directory in the sdk.

It is based on neocat's NAPT extensions: https://github.com/NeoCat/esp8266-Arduino/commit/4108c8dbced7769c75bcbb9ed880f1d3f178bcbe

Fixes some issues I had with checksums and timers and can be used for full WiFi repeater functionality. If you want to use it as a permanent replacement for liblwib.a you might want to add the option IP_NAPT_DYNAMIC = 1. With this option the memory for the NAPT tables is allocated only, if ip_napt_init(max_nat, max_portmap) is called explicitly before enabling NAPT.
