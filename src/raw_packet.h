#ifndef SIPSAK_RAW_PACKET_H
#define SIPSAK_RAW_PACKET_H

#include <stddef.h>

#define ICMP4_DESTINATION_UNREACHABLE  3
#define     ICMP4_DESTINATION_NETWORK_UNREACHABLE           0
#define     ICMP4_DESTINATION_HOST_UNRERACHABLE             1
#define     ICMP4_DESTINATION_PROTOCOL_UNREACHABLE          2
#define     ICMP4_DESTINATION_PORT_UNREACHABLE              3
#define     ICMP4_FRAGMENTATION_REQUIRED                    4
#define     ICMP4_SOURCE_ROUTE_FAILED                       5
#define     ICMP4_DESTINATION_NETWORK_UNKNOWN               6
#define     ICMP4_DESTINATION_HOST_UNKNOWN                  7
#define     ICMP4_SOURCE_HOST_ISOLATED                      8
#define     ICMP4_NETWORK_ADMINISTRATIVELY_PROHIBITED       9
#define     ICMP4_HOST_ADMINISTRATIVELY_PROHIBITED          10
#define     ICMP4_NETWORK_UNREACHABLE_FOR_TOS               11
#define     ICMP4_HOST_UNREACHABLE_FOR_TOS                  12
#define     ICMP4_COMMUNICATION_ADMINISTRATIVELY_PROHIBITED 13
#define     ICMP4_HOST_PRECEDENCE_VIOLATION                 14
#define     ICMP4_PRECEDENCE_CUTOFF_IN_EFFECT               15

#define ICMP4_REDIRECT                                      5
#define     ICMP4_REDIRECT_DATAGRAM_FOR_NETWORK             0
#define     ICMP4_REDIRECT_DATAGRAM_FOR_HOST                1
#define     ICMP4_REDIRECT_DATAGRAM_FOR_TOS_AND_NETWORK     2
#define     ICMP4_REDIRECT_DATAGRAM_FOR_TOS_AND_HOST        3

#define ICMP4_TIME_EXCEEDED                                 11
#define     ICMP4_TTL_EXPIRED_IN_TRANSIT                    0
#define     ICMP4_FRAGMENT_REASSEMBLY_TIME_EXCEEDED         1

#define ICMP4_PARAMETER_PROBLEM                             12
#define     ICMP4_POINTER_INDICATES_ERROR                   0
#define     ICMP4_MISSING_A_REQUIRED_OPTION                 1
#define     ICMP4_BAD_LENGTH                                2


#define ICMP6_DESTINATION_UNREACHABLE                       1
#define ICMP6_PACKET_TOO_BIG    2
#define ICMP6_TIME_EXCEEDED 3
#define ICMP6_PARAMETER_PROBLEM 4





#define ICMP4_IP_HEADER_INDEX 8


int ipv4_ihl(unsigned char const *buf, size_t buf_len, unsigned int *res);
int ipv4_protocol(unsigned char const *buf, size_t buf_len, unsigned int *res);
int icmp4_type(unsigned char const *buf, size_t buf_len, unsigned int *res);
int icmp4_code(unsigned char const *buf, size_t buf_len, unsigned int  *res);
int icmp4_ip_header(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res);
int udp_src_port(unsigned char const *buf, size_t buf_size, unsigned int *res);
int udp_dst_port(unsigned char const *buf, size_t buf_size, unsigned int *res);

int ipv6_payload_length(unsigned char const *buf, size_t buf_len, unsigned int *res);
int ipv6_next_header(unsigned char const *buf, size_t buf_len, unsigned int *res);
int ipv6_next_payload(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res);


int icmp6_type(unsigned char const *buf, size_t buf_len, unsigned int *res);
int icmp6_code(unsigned char const *buf, size_t buf_len, unsigned int *res);
int icmp6_type(unsigned char const *buf, size_t buf_len, unsigned int *res);
int icmp6_code(unsigned char const *buf, size_t buf_len, unsigned int  *res);
int icmp6_ip_header(unsigned char const *buf, size_t buf_len, size_t *new_size, unsigned char const **res);

#endif