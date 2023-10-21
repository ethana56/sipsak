#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "error.h"

sipsak_err translate_gai_err(int gai_err) {
    switch (gai_err) {
        case EAI_AGAIN:
            return SIPSAK_ERR_TEMP_RES;
        case EAI_BADFLAGS:
            return SIPSAK_ERR_GAI_BAD_FLAGS;
        case EAI_FAMILY:
            return SIPSAK_ERR_ADDR_FAMILY;
        case EAI_MEMORY:
            return SIPSAK_ERR_MEM;
        case EAI_NONAME:
            return SIPSAK_ERR_HOST_RES;
        case EAI_FAIL:
            return SIPSAK_ERR_FATAL_RES;
        case EAI_SYSTEM:
            return SIPSAK_ERR_SYS;
        case 0:
            return SIPSAK_ERR_SUCCESS;
        default:
            return SIPSAK_ERR_RES_UNKNOWN;
    }
}

char const *sipsak_strerror(sipsak_err err) {
    switch (err) {
        case SIPSAK_ERR_SUCCESS:
            return "success";
        case SIPSAK_ERR_TEMP_RES:
            return "temporary failure in name resolution";
        case SIPSAK_ERR_HOST_RES:
            return "cannot resolve host";
        case SIPSAK_ERR_FATAL_RES:
            return "permanent failure resolving host";
        case SIPSAK_ERR_REBIND_TCP:
            return "failure in rebinding tcp socket";
        case SIPSAK_ERR_ADDR_FAMILY:
            return "the address family is not support";
        case SIPSAK_ERR_RES_UNKNOWN:
            return "error resolving address";
        case SIPSAK_ERR_GAI_BAD_FLAGS:
            return "unsupported getaddrinfo flags";
        case SIPSAK_ERR_NO_IP:
            return "could not find suitable ip address";
        case SIPSAK_ERR_MEM:
            return "memory allocation failure";
        case SIPSAK_ERR_SEND:
            return "send failure";
        case SIPSAK_ERR_EOF:
            return "EOF";
        case SIPSAK_ERR_SYS:
            return "system error";
        case SIPSAK_ERR_RAWBUF_SIZE:
            return "rawbuf too small";
        case SIPSAK_ERR_ICMP4:
            return "icmp4";
        case SIPSAK_ERR_ICMP6:
            return "icmp6";
        case SIPSAK_ERR_ICMP_UNOWNED:
            return "icmp response not meant for this socket";
        case SIPSAK_ERR_ICMP_UNOWNED_PROTO:
            return "icmp response not meant for this socket. Wrong protocol";
        case SIPSAK_ERR_ICMP_UNOWNED_TYPE:
            return "icmp response not meant for this socket. Wrong type";
        case SIPSAK_ERR_ICMP_UNOWNED_PORT:
            return "icmp response not meant for this socket. Wrong port";
        
        default:
            return "unknown error";
    }
}

int check_errno(sipsak_err err) {
    switch (err) {
        case SIPSAK_ERR_SYS:
        case SIPSAK_ERR_REBIND_TCP:
        case SIPSAK_ERR_NO_IP:
        case SIPSAK_ERR_SEND:
            return 1;
        default:
            return 0;
    }
}