#ifndef SIPSAK_ERROR_H
#define SIPSAK_ERROR_H

typedef enum {
  SIPSAK_ERR_SUCCESS,
  SIPSAK_ERR_TEMP_RES,
  SIPSAK_ERR_HOST_RES,
  SIPSAK_ERR_FATAL_RES,
  SIPSAK_ERR_REBIND_TCP, /* Check errno */
  SIPSAK_ERR_ADDR_FAMILY,

  SIPSAK_ERR_RES_UNKNOWN,

  SIPSAK_ERR_GAI_BAD_FLAGS,

  SIPSAK_ERR_NO_IP,
  SIPSAK_ERR_MEM,

  SIPSAK_ERR_UNKNOWN_SIP_TRANSPORT,

  SIPSAK_ERR_EOF,

  SIPSAK_ERR_SYS
} sipsak_err;

sipsak_err translate_gai_err(int gai_err);
char const *sipsak_strerror(sipsak_err err);
int check_errno(sipsak_err err);

#endif