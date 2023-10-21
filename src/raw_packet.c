#include <stddef.h>
#include <stdlib.h>

#include "raw_packet.h"
#include "helper.h"

#define IHL_INDEX 0

int ipv4_ihl(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 1) return -1;
    *res = buf[IHL_INDEX] & 0x0f;
    return 0;
}

int ipv4_protocol(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 10) return -1;
    *res = buf[9];
    return 0;
}

int icmp4_type(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 1) return -1;
    *res = buf[0];
    return 0;
}

int icmp4_code(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 2) return -1;
    *res = buf[1];
    return 0;
}

int icmp4_ip_header(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res) {
    if (buf_len < 9) return -1;
    *new_size = buf_len - 8;
    *res = &buf[8];
    return 0;
}

int udp_src_port(unsigned char const *buf, size_t buf_size, unsigned int *res) {
    if (buf_size < 2) return -1;
    *res = read_big_endian_16(buf);
    return 0;
}

int udp_dst_port(unsigned char const *buf, size_t buf_size, unsigned int *res) {
    if (buf_size < 4) return -1;
    *res = read_big_endian_16(&buf[2]);
    return 0;
}

int ipv6_payload_length(unsigned char const *buf, size_t buf_size, unsigned int *res) {
    if (buf_size < 6) return -1;
    *res = read_big_endian_16(&buf[4]);
    return 0;
}

int ipv6_next_header(unsigned char const *buf, size_t buf_size, unsigned int *res) {
    if (buf_size < 7) return -1;
    *res = buf[6];
    return 0;
}

int ipv6_next_payload(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res) {
    if (buf_len < 41) return -1;
    *new_size = buf_len - 40;
    *res = &buf[40];
    return 0;
}

int icmp6_type(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 1) return -1;
    *res = buf[0];
    return 0;
}

int icmp6_code(unsigned char const *buf, size_t buf_len, unsigned int *res) {
    if (buf_len < 2) return -1;
    *res = buf[1];
    return 0;
}

int icmp6_ip_header(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res) {
    if (buf_len < 9) return -1;
    *new_size = buf_len - 8;
    *res = &buf[8];
    return 0;
}


