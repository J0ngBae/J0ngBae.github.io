---
title: "EAPoL Protocol 흐름 분석 - [Baseband Hacking Project]"
date: 2025-02-01 +0900
categories: [Project, Baseband Hacking]
tags: ['iot', 'wireless', 'eapol']
image:
    path: "/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image2.png"
    alt: "hostap"
    lqip: "/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image2.png"
---

## hostapd

![image.png](/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image1.png)

### hostapd source code

- hostapd verison 확인
    
    ```
    /tmp/tools # hostapd -v
    hostapd v2.9
    User space daemon for IEEE 802.11 AP management,
    IEEE 802.1X/WPA/WPA2/EAP/RADIUS Authenticator
    Copyright (c) 2002-2019, Jouni Malinen <j@w1.fi> and contributors
    ```
    

- https://w1.fi/cgit/hostap/
- 해당 페이지에서 소스코드 관리
    
    ![image.png](/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image2.png)
    

### ltrace

- 7703 pid를 ltrace를 통해 추적
- 인증시에 `recvfrom()` 함수 호출하는 것을 확인

```
recvfrom(12, 0xbe8b9ea8, 3000, 0)                                         = 123
memset(0xbe8b9e00, 0, 168, 16)                                            = 0xbe8b9e00
vsnprintf(0, 0, 0xc6aa0, 0xbe8b9d14)                                      = 28
malloc(29, 0xc6ab6, 0, 0xbe8b9c00)                                        = 0xccfb78
snprintf(0xbe8b9c6c, 130, 0xceb28, 0xccead0)                              = 5
vsnprintf(0xccfb78, 29, 0xc6aa0, 0xbe8b9d14)                              = 28
memset(0xccfb78, 0, 29, 0x14244)                                          = 0xccfb78
free(0xccfb78, 0, -1, 0xccfb95)         
```

## EAPoL(Extensible Authentication Protocol over LAN)

- 802.1x 에서 사용되는 네트워크 인증 프로토콜이다.
- Supplicant와 Authenticator 간에 사용되는 캡슐화 프로토콜

## EAPoL 호출 흐름

> `i802_init()` → `handle_eapol()` → `drv_event_eapol_rx()` → `wpa_supplicant_event()` → `wpa_supplicant_rx_eapol()` → `ieee802_1x_receive()` → `wpa_receive()`

### i802_init()
- `i802_init()` 에서 `handle_eapol()` 함수를 이벤트로 등록한다.
- 함수 등록과 함께 해당 함수가 사용할 socket descriptor도 등록한다.

```c
static void *i802_init(struct hostapd_data *hapd,
		       struct wpa_init_params *params)
{
	struct wpa_driver_nl80211_data *drv;
	struct i802_bss *bss;
	size_t i;
	char master_ifname[IFNAMSIZ];
	int ifindex, br_ifindex = 0;
	int br_added = 0;
	
	...
	
		drv->eapol_sock = socket(PF_PACKET, SOCK_DGRAM, htons(ETH_P_PAE));
	if (drv->eapol_sock < 0) {
		wpa_printf(MSG_ERROR, "nl80211: socket(PF_PACKET, SOCK_DGRAM, ETH_P_PAE) failed: %s",
			   strerror(errno));
		goto failed;
	}

	if (eloop_register_read_sock(drv->eapol_sock, handle_eapol, drv, NULL))
	{
		wpa_printf(MSG_INFO, "nl80211: Could not register read socket for eapol");
		goto failed;
	}
```

### handle_eapol()
- 해당 소켓으로 데이터가 수신되면 `handle_eapol()` 함수를 호출한다.
- `recvfrom()` 을 통해 데이터가 `buf` 변수에 저장된다.
- `have_ifidx()` 는 network Interface 검사
- `have_ifidx()` 를 만족하면 `drv_event_eapol_rx()` 호출

```c
static void handle_eapol(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct wpa_driver_nl80211_data *drv = eloop_ctx;
	struct sockaddr_ll lladdr;
	unsigned char buf[3000];
	int len;
	socklen_t fromlen = sizeof(lladdr);

	len = recvfrom(sock, buf, sizeof(buf), 0,
		       (struct sockaddr *)&lladdr, &fromlen);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "nl80211: EAPOL recv failed: %s",
			   strerror(errno));
		return;
	}

	if (have_ifidx(drv, lladdr.sll_ifindex, IFIDX_ANY))
		drv_event_eapol_rx(drv->ctx, lladdr.sll_addr, buf, len);
}
```

### drv_event_eapol_rx()
- `wpa_event_data` 열거체에 송신측 MAC 주소, 데이터, 데이터 길이를 저장
- 이후 `EVENT_EAPOL_RX` 매크로와 함계 `wpa_supplicant_event()` 함수를 호출

```c
static inline void drv_event_eapol_rx(void *ctx, const u8 *src, const u8 *data,
				      size_t data_len)
{
	union wpa_event_data event;
	os_memset(&event, 0, sizeof(event));
	event.eapol_rx.src = src;
	event.eapol_rx.data = data;
	event.eapol_rx.data_len = data_len;
	wpa_supplicant_event(ctx, EVENT_EAPOL_RX, &event);
}
```

### wpa_supplicant_event()
- switch ~ case문을 통해 `EVENT_EAPOL_RX` 의 로직을 따라가면 `wpa_supplicant_rx_eapol()` 을 호출함.

```c
void wpa_supplicant_event(void *ctx, enum wpa_event_type event,
			  union wpa_event_data *data)
{
	struct wpa_supplicant *wpa_s = ctx;
	int resched;
	
	...
	
	case EVENT_EAPOL_RX:
		wpa_supplicant_rx_eapol(wpa_s, data->eapol_rx.src,
					data->eapol_rx.data,
					data->eapol_rx.data_len);
		break;
		
...
```

### wpa_supplicant_rx_eapol()
- BSSID와 src_addr 를 비교하여 현재 연결되어 있는 기기인지 확인
- 아니면 인증과정 진행

```c
void wpa_supplicant_rx_eapol(void *ctx, const u8 *src_addr,
			     const u8 *buf, size_t len)
{
	struct wpa_supplicant *wpa_s = ctx;

	wpa_dbg(wpa_s, MSG_DEBUG, "RX EAPOL from " MACSTR, MAC2STR(src_addr));
	wpa_hexdump(MSG_MSGDUMP, "RX EAPOL", buf, len);

#ifdef CONFIG_TESTING_OPTIONS
	if (wpa_s->ignore_auth_resp) {
		wpa_printf(MSG_INFO, "RX EAPOL - ignore_auth_resp active!");
		return;
	}
#endif /* CONFIG_TESTING_OPTIONS */

	if (wpa_s->wpa_state < WPA_ASSOCIATED ||
	    (wpa_s->last_eapol_matches_bssid &&
#ifdef CONFIG_AP
	     !wpa_s->ap_iface &&
#endif /* CONFIG_AP */
	     os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) != 0)) {
		/*
		 * There is possible race condition between receiving the
		 * association event and the EAPOL frame since they are coming
		 * through different paths from the driver. In order to avoid
		 * issues in trying to process the EAPOL frame before receiving
		 * association information, lets queue it for processing until
		 * the association event is received. This may also be needed in
		 * driver-based roaming case, so also use src_addr != BSSID as a
		 * trigger if we have previously confirmed that the
		 * Authenticator uses BSSID as the src_addr (which is not the
		 * case with wired IEEE 802.1X).
		 */
		wpa_dbg(wpa_s, MSG_DEBUG, "Not associated - Delay processing "
			"of received EAPOL frame (state=%s bssid=" MACSTR ")",
			wpa_supplicant_state_txt(wpa_s->wpa_state),
			MAC2STR(wpa_s->bssid));
		wpabuf_free(wpa_s->pending_eapol_rx);
		wpa_s->pending_eapol_rx = wpabuf_alloc_copy(buf, len);
		if (wpa_s->pending_eapol_rx) {
			os_get_reltime(&wpa_s->pending_eapol_rx_time);
			os_memcpy(wpa_s->pending_eapol_rx_src, src_addr,
				  ETH_ALEN);
		}
		return;
	}

	wpa_s->last_eapol_matches_bssid =
		os_memcmp(src_addr, wpa_s->bssid, ETH_ALEN) == 0;

#ifdef CONFIG_AP
	if (wpa_s->ap_iface) {
		wpa_supplicant_ap_rx_eapol(wpa_s, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_AP */

	if (wpa_s->key_mgmt == WPA_KEY_MGMT_NONE) {
		wpa_dbg(wpa_s, MSG_DEBUG, "Ignored received EAPOL frame since "
			"no key management is configured");
		return;
	}

	if (wpa_s->eapol_received == 0 &&
	    (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK) ||
	     !wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) ||
	     wpa_s->wpa_state != WPA_COMPLETED) &&
	    (wpa_s->current_ssid == NULL ||
	     wpa_s->current_ssid->mode != WPAS_MODE_IBSS)) {
		/* Timeout for completing IEEE 802.1X and WPA authentication */
		int timeout = 10;

		if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt) ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_IEEE8021X_NO_WPA ||
		    wpa_s->key_mgmt == WPA_KEY_MGMT_WPS) {
			/* Use longer timeout for IEEE 802.1X/EAP */
			timeout = 70;
		}

#ifdef CONFIG_WPS
		if (wpa_s->current_ssid && wpa_s->current_bss &&
		    (wpa_s->current_ssid->key_mgmt & WPA_KEY_MGMT_WPS) &&
		    eap_is_wps_pin_enrollee(&wpa_s->current_ssid->eap)) {
			/*
			 * Use shorter timeout if going through WPS AP iteration
			 * for PIN config method with an AP that does not
			 * advertise Selected Registrar.
			 */
			struct wpabuf *wps_ie;

			wps_ie = wpa_bss_get_vendor_ie_multi(
				wpa_s->current_bss, WPS_IE_VENDOR_TYPE);
			if (wps_ie &&
			    !wps_is_addr_authorized(wps_ie, wpa_s->own_addr, 1))
				timeout = 10;
			wpabuf_free(wps_ie);
		}
#endif /* CONFIG_WPS */

		wpa_supplicant_req_auth_timeout(wpa_s, timeout, 0);
	}
	wpa_s->eapol_received++;

	if (wpa_s->countermeasures) {
		wpa_msg(wpa_s, MSG_INFO, "WPA: Countermeasures - dropped "
			"EAPOL packet");
		return;
	}

#ifdef CONFIG_IBSS_RSN
	if (wpa_s->current_ssid &&
	    wpa_s->current_ssid->mode == WPAS_MODE_IBSS) {
		ibss_rsn_rx_eapol(wpa_s->ibss_rsn, src_addr, buf, len);
		return;
	}
#endif /* CONFIG_IBSS_RSN */

	/* Source address of the incoming EAPOL frame could be compared to the
	 * current BSSID. However, it is possible that a centralized
	 * Authenticator could be using another MAC address than the BSSID of
	 * an AP, so just allow any address to be used for now. The replies are
	 * still sent to the current BSSID (if available), though. */

	os_memcpy(wpa_s->last_eapol_src, src_addr, ETH_ALEN);
	if (!wpa_key_mgmt_wpa_psk(wpa_s->key_mgmt) &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_OWE &&
	    wpa_s->key_mgmt != WPA_KEY_MGMT_DPP &&
	    eapol_sm_rx_eapol(wpa_s->eapol, src_addr, buf, len) > 0)
		return;
	wpa_drv_poll(wpa_s);
	if (!(wpa_s->drv_flags & WPA_DRIVER_FLAGS_4WAY_HANDSHAKE_PSK))
		wpa_sm_rx_eapol(wpa_s->wpa, src_addr, buf, len);
	else if (wpa_key_mgmt_wpa_ieee8021x(wpa_s->key_mgmt)) {
		/*
		 * Set portValid = TRUE here since we are going to skip 4-way
		 * handshake processing which would normally set portValid. We
		 * need this to allow the EAPOL state machines to be completed
		 * without going through EAPOL-Key handshake.
		 */
		eapol_sm_notify_portValid(wpa_s->eapol, TRUE);
	}
}
```

### ieee802_1x_receive()

- EAPOL 프레임 처리를 담당함.
- `wpa_receive()` 호출

```c
key = (struct ieee802_1x_eapol_key *) (hdr + 1);
if (datalen >= sizeof(struct ieee802_1x_eapol_key) &&
    hdr->type == IEEE802_1X_TYPE_EAPOL_KEY &&
    (key->type == EAPOL_KEY_TYPE_WPA ||
     key->type == EAPOL_KEY_TYPE_RSN)) {
	wpa_receive(hapd->wpa_auth, sta->wpa_sm, (u8 *) hdr,
		    sizeof(*hdr) + datalen);
	return;
}
```

### wpa_receive()

- 인증 절차 진행
- 임의로 보낸 패킷인 `data` 를 사용하는 부분을 중점으로 봄
- memory corruption이 일어날 만한 부분이 보이지 않음.

```c
void wpa_receive(struct wpa_authenticator *wpa_auth,
		 struct wpa_state_machine *sm,
		 u8 *data, size_t data_len)
{
	struct ieee802_1x_hdr *hdr;
	struct wpa_eapol_key *key;
	u16 key_info, key_data_length;
	enum { PAIRWISE_2, PAIRWISE_4, GROUP_2, REQUEST } msg;
	char *msgtxt;
	struct wpa_eapol_ie_parse kde;
	const u8 *key_data;
	size_t keyhdrlen, mic_len;
	u8 *mic;

	if (wpa_auth == NULL || !wpa_auth->conf.wpa || sm == NULL)
		return;
	wpa_hexdump(MSG_MSGDUMP, "WPA: RX EAPOL data", data, data_len);

	mic_len = wpa_mic_len(sm->wpa_key_mgmt, sm->pmk_len);
	keyhdrlen = sizeof(*key) + mic_len + 2;

	if (data_len < sizeof(*hdr) + keyhdrlen) {
		wpa_printf(MSG_DEBUG, "WPA: Ignore too short EAPOL-Key frame");
		return;
	}

	hdr = (struct ieee802_1x_hdr *) data;
	key = (struct wpa_eapol_key *) (hdr + 1);
	mic = (u8 *) (key + 1);
	key_info = WPA_GET_BE16(key->key_info);
	key_data = mic + mic_len + 2;
	key_data_length = WPA_GET_BE16(mic + mic_len);
	wpa_printf(MSG_DEBUG, "WPA: Received EAPOL-Key from " MACSTR
		   " key_info=0x%x type=%u mic_len=%u key_data_length=%u",
		   MAC2STR(sm->addr), key_info, key->type,
		   (unsigned int) mic_len, key_data_length);
	wpa_hexdump(MSG_MSGDUMP,
		    "WPA: EAPOL-Key header (ending before Key MIC)",
		    key, sizeof(*key));
	wpa_hexdump(MSG_MSGDUMP, "WPA: EAPOL-Key Key MIC",
		    mic, mic_len);
	if (key_data_length > data_len - sizeof(*hdr) - keyhdrlen) {
		wpa_printf(MSG_INFO, "WPA: Invalid EAPOL-Key frame - "
			   "key_data overflow (%d > %lu)",
			   key_data_length,
			   (unsigned long) (data_len - sizeof(*hdr) -
					    keyhdrlen));
		return;
	}
	
	...
```

## test Code

- raw packet code
    
    ```c
    #include <stdio.h>
    #include <string.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <net/ethernet.h>
    #include <sys/ioctl.h>
    #include <net/if.h>
    #include <netpacket/packet.h>
    
    #define BUF_SIZ 1024
    
    int main(int argc, char* argv[]){
        int sock;
        // char ifName[IFNAMSIZ] = "wlx588694ffb5a5";
        char ifName[IFNAMSIZ] = "eth0";
        char sendbuf[BUF_SIZ];
        unsigned char dest_mac[6] = {0xc0, 0x06, 0xc3, 0x65, 0xf9, 0x5b};
        int len;
        int tx_len = 0;
        struct ifreq if_mac;
        struct ifreq if_idx;
        struct ether_header *eh = (struct ether_header *)sendbuf;
        struct sockaddr_ll socket_address;
        //unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    
        sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE));
        if(sock < 0){
            perror("socket");
            return 1;
        }
    
        
        memset(&if_idx, 0, sizeof(struct ifreq));
        strncpy(if_idx.ifr_name, ifName, IFNAMSIZ - 1);
        if(ioctl(sock, SIOCGIFINDEX, &if_idx) < 0){
    	perror("ioctl");
    	return 1;
        }
    
        memset(&if_mac, 0, sizeof(struct ifreq));
        strncpy(if_mac.ifr_name, ifName, IFNAMSIZ - 1);
        if(ioctl(sock, SIOCGIFHWADDR, &if_mac) < 0){
    	perror("ioctl");
    	return 1;
        }
    
        printf("iface name: %s\n", ifName);
    
        printf("MAC Address -> ");
        for(int i = 0; i < 6; i++){
            eh->ether_shost[i] = ((uint8_t *)&if_mac.ifr_hwaddr.sa_data)[i];
    	printf("%02x", eh->ether_shost[i]);
    	if(i < 5){
    	    printf(":");
    	}	
        }
        printf("\n");
    
        memcpy(eh->ether_dhost, dest_mac, 6);
    
        printf("Dhost MAC -> ");
        for(int i = 0; i < 6; i++){
    	printf("%02x", eh->ether_dhost[i]);
    	if(i < 5){
    	    printf(":");
    	}	
        }
        printf("\n");
    
        eh->ether_type = htons(ETH_P_PAE);
        tx_len += sizeof(struct ether_header);
    
        for(int i = 0; i < 32; i++){
    	    sendbuf[tx_len++]  = 'A';
        }
    
        socket_address.sll_ifindex = if_idx.ifr_ifindex;
        socket_address.sll_halen = ETH_ALEN;
        memcpy(socket_address.sll_addr, dest_mac, ETH_ALEN);
        printf("");
    
        if(sendto(sock, sendbuf, 32, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0) {
            perror("sendto");
            return 1;
        }
        printf("[+] Send Complete\n");
    
        return 0;
    }
    
    ```
    

- wireshark를 통해 패킷 확인

![image.png](/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image3.png)

`handle_eapol`  로직으로 들어온 것을 확인

![image.png](/assets/img/posts/2025-02-01-EAPoL-Protocol-흐름-분석/image4.png)