#include "net.h"
#include "ip.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"

/**
 * @brief 处理一个收到的数据包
 *
 * @param buf 要处理的数据包
 * @param src_mac 源mac地址
 */
void ip_in(buf_t *buf, uint8_t *src_mac) {
    if (buf->len < sizeof(ip_hdr_t))
        return;
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    if (ip_hdr->version != IP_VERSION_4 ||
        swap16(ip_hdr->total_len16) > buf->len)
        return;
    uint16_t checksum_got = ip_hdr->hdr_checksum16;
    ip_hdr->hdr_checksum16 = 0;
    if (checksum16((uint16_t *)ip_hdr, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE) !=
        checksum_got)
        return;
    ip_hdr->hdr_checksum16 = checksum_got;
    if (memcmp(ip_hdr->dst_ip, net_if_ip, NET_IP_LEN) != 0)
        return;
    if (buf->len > swap16(ip_hdr->total_len16))
        buf_remove_padding(buf, buf->len - swap16(ip_hdr->total_len16));
    uint8_t protocol = ip_hdr->protocol, *src_ip = ip_hdr->src_ip;
    if (protocol != NET_PROTOCOL_ICMP && protocol != NET_PROTOCOL_UDP) {
        icmp_unreachable(buf, src_ip, ICMP_CODE_PROTOCOL_UNREACH);
        return;
    }
    buf_remove_header(buf, ip_hdr->hdr_len * IP_HDR_LEN_PER_BYTE);
    net_in(buf, protocol, src_ip);
}

/**
 * @brief 处理一个要发送的ip分片
 *
 * @param buf 要发送的分片
 * @param ip 目标ip地址
 * @param protocol 上层协议
 * @param id 数据包id
 * @param offset 分片offset，必须被8整除
 * @param mf 分片mf标志，是否有下一个分片
 */
void ip_fragment_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol, int id,
                     uint16_t offset, int mf) {
    buf_add_header(buf, sizeof(ip_hdr_t));
    ip_hdr_t *ip_hdr = (ip_hdr_t *)buf->data;
    ip_hdr->version = IP_VERSION_4;
    ip_hdr->hdr_len = 5;
    ip_hdr->tos = 0;
    ip_hdr->total_len16 = swap16(buf->len);
    ip_hdr->id16 = swap16(id);
    ip_hdr->flags_fragment16 =
        swap16((mf ? IP_MORE_FRAGMENT : 0) | (offset >> 3));
    ip_hdr->ttl = IP_DEFALUT_TTL;
    ip_hdr->protocol = protocol;
    ip_hdr->hdr_checksum16 = 0;
    memcpy(ip_hdr->src_ip, net_if_ip, NET_IP_LEN);
    memcpy(ip_hdr->dst_ip, ip, NET_IP_LEN);
    ip_hdr->hdr_checksum16 = checksum16((uint16_t *)ip_hdr, sizeof(ip_hdr_t));
    arp_out(buf, ip);
}

/**
 * @brief 处理一个要发送的ip数据包
 *
 * @param buf 要处理的包
 * @param ip 目标ip地址
 * @param protocol 上层协议
 */
void ip_out(buf_t *buf, uint8_t *ip, net_protocol_t protocol) {
    static int id = 0;
    int ip_mtu = ETHERNET_MAX_TRANSPORT_UNIT - sizeof(ip_hdr_t);
    uint16_t offset = 0;
    for (offset = 0; offset + ip_mtu < buf->len; offset += ip_mtu) {
        buf_t ip_buf;
        buf_init(&ip_buf, ip_mtu);
        memcpy(ip_buf.data, buf->data + offset, ip_mtu);
        ip_fragment_out(&ip_buf, ip, protocol, id, offset, 1);
    }
    if (offset < buf->len) {
        buf_t ip_buf;
        buf_init(&ip_buf, buf->len - offset);
        memcpy(ip_buf.data, buf->data + offset, buf->len - offset);
        ip_fragment_out(&ip_buf, ip, protocol, id, offset, 0);
    }
    id++;
}

/**
 * @brief 初始化ip协议
 *
 */
void ip_init() { net_add_protocol(NET_PROTOCOL_IP, ip_in); }