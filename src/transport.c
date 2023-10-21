/*
 * Copyright (C) 2005-2022 Nils Ohlmeier
 *
 * This file belongs to sipsak, a free sip testing tool.
 *
 * sipsak is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * sipsak is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include "sipsak.h"

#include <time.h>
#include <errno.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_SYS_POLL_H
# include <sys/poll.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif

#include "transport.h"
#include "shoot.h"

#ifdef RAW_SUPPORT
# ifdef HAVE_NETINET_IN_SYSTM_H 
#  include <netinet/in_systm.h>
# endif
# ifdef HAVE_NETINET_IP_H
#  include <netinet/ip.h>
# endif
# ifdef HAVE_NETINET_IP_ICMP_H
#  include <netinet/ip_icmp.h>
# endif
# ifdef HAVE_NETINET_UDP_H
#  define __FAVOR_BSD
#  include <netinet/udp.h>
# endif

#include <netinet/icmp6.h>
#endif /* RAW_SUPPORT */

#ifdef WITH_TLS_TRANSP
# ifdef USE_GNUTLS
#  include <stdio.h>
#  include <stdlib.h>
#  include <string.h>
#  include <sys/types.h>
#  include <sys/socket.h>
#  include <netinet/in.h>
#  include <arpa/inet.h>
#  include <unistd.h>
#  include <gnutls/gnutls.h>
#  include <gnutls/x509.h>
# else
#  ifdef USE_OPENSSL
#   define _BSD_SOURCE 1
#   include <assert.h>
#   include <errno.h>
#   include <limits.h>
#   include <stdio.h>
#   include <stdlib.h>
#   include <string.h>
#   include <time.h>
#   include <ctype.h>
#   include <openssl/bio.h>
#   include <openssl/crypto.h>
#   include <openssl/evp.h>
#   include <openssl/x509.h>
#   include <openssl/x509v3.h>
#   include <openssl/ssl.h>
#   include <openssl/engine.h>
#   include <openssl/err.h>
#   include <openssl/rand.h>
#  endif
# endif
#endif /* WITH_TLS_TRANSP */

#define RAW_HEADER_MAXLEN 512

#include "exit_code.h"
#include "helper.h"
#include "header_f.h"
#include "error.h"
#include "raw_packet.h"

char *transport_str;
char target_dot[INET6_ADDRSTRLEN], source_dot[INET6_ADDRSTRLEN];

#ifdef RAW_SUPPORT
int rawsock;
#endif

#ifdef USE_GNUTLS
gnutls_session_t tls_session;
//gnutls_anon_client_credentials_t anoncred;
gnutls_certificate_credentials_t xcred;
#else
# ifdef USE_OPENSSL
SSL_CTX* ctx;
SSL* ssl;
# endif
#endif

#ifdef WITH_TLS_TRANSP
# ifdef USE_GNUTLS
void check_alert(gnutls_session_t session, int ret) {
	int last_alert;

	if (ret == GNUTLS_E_WARNING_ALERT_RECEIVED ||
			ret == GNUTLS_E_FATAL_ALERT_RECEIVED) {
		last_alert = gnutls_alert_get(session);
		printf("Received TLS alert: '%d': %s\n", last_alert,
			gnutls_alert_get_name(last_alert));
	}
}

/* all the available CRLs */
gnutls_x509_crl_t *global_crl_list;
int global_crl_list_size;

/* all the available  trusted CAs */
gnutls_x509_crt_t *global_ca_list;
int global_ca_list_size;

/* verifies a certificate against an other certificate which is supposed to 
 * be it's issuer. Also checks the crl_list of the certificate is revoked.
 */
static void verify_cert2(gnutls_x509_crt_t crt, gnutls_x509_crt_t issuer,
			gnutls_x509_crl_t *crl_list, int crl_list_size) {
	unsigned int output;
	time_t now = time(0);
	size_t name_size;
	char name[64];

	/* print information about the certificates to be checked */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(crt, name, &name_size);

	printf("Certificate: %s\n", name);

	name_size = sizeof(name);
	gnutls_x509_crt_get_issuer_dn(crt, name, &name_size);

	printf("Issued by: %s\n", name);

	/* Get the DN of the issuer cert. */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(issuer, name, &name_size);

	printf("Checking against: %s\n", name);

	/* Do the actual verification */
	gnutls_x509_crt_verify(crt, &issuer, 1, 0, &output);

	if (output & GNUTLS_CERT_INVALID) {
		printf("Certificate not trusted!!!");
		if (output & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			printf(": no issuer was found\n");
		}
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf(": issuer is not a CA\n");
		}
	}
	else {
		printf("Certificate trusted'n");
	}

	/* Now check the expiration dates */
	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		printf("Certificate is not yet valid!\n");
	}
	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		printf("Certificate expired!\n");
	}
	/* Check if the certificate is revoked */
	if (gnutls_x509_crt_check_revocation(crt, crl_list, crl_list_size) == 1) {
		printf("Certificate is revoked!\n");
	}
}

/* Verifies a certificate against our trusted CA list. Also checks the crl_list
 * if the certificate is revoked
 */
static void verify_last_cert(gnutls_x509_crt_t crt, gnutls_x509_crt_t *ca_list,
			int ca_list_size, gnutls_x509_crl_t *crl_list, int crl_list_size) {
	unsigned int output;
	time_t now = time(0);
	size_t name_size;
	char name[64];

	/* Print information about the certificates to be checked */
	name_size = sizeof(name);
	gnutls_x509_crt_get_dn(crt, name, &name_size);
	printf("Certificate: %s\n", name);

	name_size = sizeof(name);
	gnutls_x509_crt_get_issuer_dn(crt, name, &name_size);
	printf("Issued by: %s\n", name);

	/* Do the actual verification */
	gnutls_x509_crt_verify(crt, ca_list, ca_list_size, 
			GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT, &output);
	if (output & GNUTLS_CERT_INVALID) {
		printf("Certificate not trusted!\n");
		if (output & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf(": Issuer is not a CA\n");
		}
	}
	else {
		printf("Certificate trusted\n");
	}

	/* Now check the expiration dates */
	if (gnutls_x509_crt_get_activation_time(crt) > now) {
		printf("Certificate is not yet valid!\n");
	}
	if (gnutls_x509_crt_get_expiration_time(crt) < now) {
		printf("Certificate expired!\n");
	}
	/* Check of the vertificate is revoked */
	if (gnutls_x509_crt_check_revocation(crt, crl_list, crl_list_size) == 1) {
		printf("Certificate is revoked!\n");
	}
}

/* this function will try yo verify the peer's certificate chain, ans
 * also check if the hostname matches, and the activation and expiration dates.
 */
void verify_certificate_chain(gnutls_session_t session, const char *hostname,
			const gnutls_datum_t *cert_chain, int cert_chain_length) {
	int i;
	gnutls_x509_crt_t *cert;

	cert = malloc(sizeof(*cert) * cert_chain_length);
	if (!cert) {
		printf("gnutls: failed to allocate memory for cert chain verification'n");
		return;
	}

	/* import all the certificates in the chain to native certificate format */
	for (i = 0; i < cert_chain_length; i++) {
		gnutls_x509_crt_init(&cert[i]);
		gnutls_x509_crt_import(cert[i], &cert_chain[i], GNUTLS_X509_FMT_DER);
	}

	/* if the last certificate in the chain is seld signed ignore it.
	 * that is because we want to check against our trusted certificate list
	 */
	if (gnutls_x509_crt_check_issuer(cert[cert_chain_length - 1],
				cert[cert_chain_length -1]) > 0 && cert_chain_length > 0) {
		cert_chain_length--;
	}
	/* now verify the certificates against other issuers in the chain */
	for (i = 1; i < cert_chain_length; i++) {
		verify_cert2(cert[i - 1], cert[i], global_crl_list, global_crl_list_size);
	}
	/* here we must verify the last certificate in the chain against our 
	 * trusted CA list
	 */
	verify_last_cert(cert[cert_chain_length - 1], global_ca_list, 
			global_ca_list_size, global_crl_list, global_crl_list_size);
	/* check if the name in the first certificate matches our destination */
	if (!gnutls_x509_crt_check_hostname(cert[0], hostname)) {
		printf("The certificate's owner does not match hostname '%s'\n", 
				hostname);
	}

	for (i = 0; i < cert_chain_length; i++) {
		gnutls_x509_crt_deinit(cert[i]);
	}
	return;
}

int verify_certificate_simple(gnutls_session_t session, const char *hostname,
    int ignore_ca_fail) {
	unsigned int status, cert_list_size;
	const gnutls_datum_t *cert_list;
	int ret;
	gnutls_x509_crt_t cert;

	// this verification function usese the trusted CAs in the credentials
	// structure. so you must have installed on or more CA certificates.
	ret = gnutls_certificate_verify_peers2(session, &status);

	if (ret < 0) {
		printf("gnutls verify peer failed.\n");
		return -1;
	}
	ret = 0;

	if (status & GNUTLS_CERT_INVALID) {
		ret |= -2;
		printf("The certificate is not trustworthy\n");
		if (status & GNUTLS_CERT_SIGNER_NOT_FOUND) {
			printf("The certificate hasn't got a known issuer.\n");
			ret |= -4;
		}
		if (status & GNUTLS_CERT_SIGNER_NOT_CA) {
			printf("The certificate issuer is not a CA\n");
			ret |= -8;
		}
	}
	if (status & GNUTLS_CERT_REVOKED) {
		printf("The certificate has been revoked.\n");
		ret = -16;
	}
	if (ret != 0 && ignore_ca_fail == 0) {
		return ret;
	}

	// from here on it works only with X509 certs
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509){
		printf("The server certificate is not X509.\n");
		return -32;;
	}
	if (gnutls_x509_crt_init(&cert) < 0) {
		printf("gnutls crt init failed.\n");
		return -64;
	}

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	if (cert_list == NULL) {
		printf("gnutls did not find a server certificate.\n");
		return -128;
	}

	// this not a real world check as only the first cert is checked!
	if (gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)) {
		printf("gnutls failed to parse server certificate.\n");
		return -256;
	}

	// beware here we do not check for errors
	if (gnutls_x509_crt_get_expiration_time(cert) < time(0)) {
		printf("The server certificate is expired.\n");
		return -512;
	}
	if (gnutls_x509_crt_get_activation_time(cert) > time(0)) {
		printf("The server certificate is not yet valid.\n");
		return -1024;
	}
	if (!gnutls_x509_crt_check_hostname(cert, hostname)) {
		printf("The server certificate's owner does not match hostname '%s'\n", 
			hostname);
		return -2048;
	}

	gnutls_x509_crt_deinit(cert);

	return ret;
}

static const char *bin2hex(const void *bin, size_t bin_size) {
	static char printable[110];
	const unsigned char *_bin = bin;
	char *print;
	size_t i;

	if (bin_size > 50) {
		bin_size = 50;
	}

	print = printable;
	for (i=0; i < bin_size; i++) {
		sprintf(print, "%.2x ", _bin[i]);
		print += 2;
	}

	return printable;
}

void print_x509_certificate_info(gnutls_session_t session) {
	char serial[40];
	char dn[128];
	char ctime_buf[27] = {0};
	size_t size;
	unsigned int algo, bits;
	time_t expiration_time, activation_time;
	const gnutls_datum_t *cert_list;
	unsigned int cert_list_size = 0;
	gnutls_x509_crt_t cert;

	// check if we got a X.509 cert
	if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509) {
		printf("TLS session did not receive a X.509 certificate\n");
		return;
	}

	cert_list = gnutls_certificate_get_peers(session, &cert_list_size);
	printf("Peer provided %u certificate(s)\n", cert_list_size);

	if (cert_list_size > 0) {
		// print only information about the first cert
		gnutls_x509_crt_init(&cert);
		gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER);
		printf("Certificate info:\n");
		activation_time = gnutls_x509_crt_get_activation_time(cert);
		printf("\tCertificate is valid since: %s", ctime_r(&activation_time, ctime_buf));
		expiration_time = gnutls_x509_crt_get_expiration_time(cert);
		printf("\tCertificate expires: %s", ctime_r(&expiration_time, ctime_buf));
		// print the serial number of the certificate
		size = sizeof(serial);
		gnutls_x509_crt_get_serial(cert, serial, &size);
		printf("\tCertificate serial number: %s\n", bin2hex(serial, size));
		// extract public key algorithm
		algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);
		printf("\tCertificate public key algorithm: %s\n", gnutls_pk_algorithm_get_name(algo));
		// print version of x509 cert
		printf("\tCertificate version: #%d\n", gnutls_x509_crt_get_version(cert));
		// print name of the certificate
		size = sizeof(dn);
		gnutls_x509_crt_get_dn(cert, dn, &size);
		printf("\tDN: %s\n", dn);
		// print subject alt name of the certificate
		size = sizeof(dn);
		if (gnutls_x509_crt_get_subject_alt_name(cert, 0, dn, &size, NULL) == 0) {
			printf("\tSubject Alt Name: %s\n", dn);
		}
		// print the algorithm which was used for signing the cert
		algo = gnutls_x509_crt_get_signature_algorithm(cert);
		printf("\tCA's signature algorithm: %s\n", gnutls_pk_algorithm_get_name(algo));
		// print the name of the CA
		size = sizeof(dn);
		if (gnutls_x509_crt_get_issuer_dn(cert, dn, &size) == 0) {
			printf("\tCA's DN: %s\n", dn);
		}
		// print the CA status flags if present
		if (gnutls_x509_crt_get_ca_status(cert, &algo) > 0 && algo != 0) {
			printf("\tCA status flag is set\n");
		}
		// print the fingerprint of the cert
		size = sizeof(dn);
		if (gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, dn, &size) == 0) {
			gnutls_datum_t dnraw = {.data = dn, .size = size};
			char dnhex[128];
			size = sizeof(dnhex);
			// "Note that the size of the result includes the null terminator."
			if (gnutls_hex_encode(&dnraw, dnhex, &size) == 0) {
				printf("\tFingerprint of the certificate: %s\n", dnhex);
			}
		}


		gnutls_x509_crt_deinit(cert);
	}
}

void gnutls_session_info(gnutls_session_t session) {
	const char *tmp;
	gnutls_credentials_type_t cred;
	gnutls_kx_algorithm_t kx;

	// print the key exchange algorithm name
	kx = gnutls_kx_get(session);
	tmp = gnutls_kx_get_name(kx);
	printf("Key Exchange: %s\n", tmp);

	// check the authentication type
	cred = gnutls_auth_get_type(session);
	switch(cred) {
#ifdef HAVE_GNUTLS_SRP
		case GNUTLS_CRD_SRP:
			printf("SRP session with username %s\n",
				gnutls_srp_server_get_username(session));
			break;
#endif // HAVE_GNUTLS_SRP
		case GNUTLS_CRD_ANON:
			printf("Anonymous DH using prime of %d bits\n", 
				gnutls_dh_get_prime_bits(session));
			break;
		case GNUTLS_CRD_CERTIFICATE:
			// check if we have been using ephemeral DH
			if (kx == GNUTLS_KX_DHE_RSA || kx == GNUTLS_KX_DHE_DSS) {
				printf("Ephemeral DH using prime of %d bits\n",
					gnutls_dh_get_prime_bits(session));
			}
			// print certificate informations if available
			print_x509_certificate_info(session);
			break;
		default:
			printf("UNKNOWN GNUTLS authentication type!!!\n");
	}

	// print protocols name
	tmp = gnutls_protocol_get_name(gnutls_protocol_get_version(session));
	printf("Protocol: %s\n", tmp);

	// print certificate type
	tmp = gnutls_certificate_type_get_name(gnutls_certificate_type_get(session));
	printf("Certificate Type: %s\n", tmp);

	// print the compression algorithm
	tmp = gnutls_compression_get_name(gnutls_compression_get(session));
	printf("Compression: %s\n", tmp);

	// print name of the cipher
	tmp = gnutls_cipher_get_name(gnutls_cipher_get(session));
	printf("Cipher: %s\n", tmp);

	// print the MAC algorithm
	tmp = gnutls_mac_get_name(gnutls_mac_get(session));
	printf("MAC: %s\n", tmp);
}
# else
#  ifdef USE_OPENSSL
void set_tls_options() {
#if OPENSSL_VERSION_NUMBER >= 0x0009070000 /* 0.9.7 */
	SSL_CTX_set_options(ctx, SSL_OP_ALL |
							SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION |
							SSL_OP_CIPHER_SERVER_PREFERENCE);
#else
	SSL_CTX_set_options(ctx, SSL_OP_ALL);
#endif
}

void create_tls_ctx() {
	SSL_METHOD *method = NULL;

	method = TLSv1_method();
	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		ERR_print_errors_fp(stderr);
		perror("create_tls_ctx: failed to create TLS ctx");
		exit_code(2, __PRETTY_FUNCTION__, "failed to create TLS ctx");
	}
	/*if (!SSL_CTX_use_certificate_chain_file(ctx, cert_file)) {
		perror("create_tls_ctx: failed to load certificate file");
		exit_code(2);
	}
	if (SSL_CTX_load_verify_locations(ctx, ca_file, 0) != 1) {
		perror("create_tls_ctx: failed to load CA cert");
		exit_code(2);
	}
	SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_file));
	if (SSL_CTX_get_client_CA_list(ctx) == 0) {
		perror("create_tls_ctx: failed to set client CA list");
		exit_code(2);
	}*/
	SSL_CTX_set_cipher_list(ctx, 0);
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);
	SSL_CTX_set_verify_depth(ctx, 5);
	set_tls_options();
	SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_OFF);
	SSL_CTX_set_session_id_context(ctx, 0, 0);
}

void tls_dump_cert_info(char* s, X509* cert) {
	char *subj, *issuer;

	subj = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
	issuer = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	printf("%s subject: '%s'\n", s ? s: "", subj);
	printf("%s issuer: '%s'\n", s ? s : "", issuer);
	OPENSSL_free(subj);
	OPENSSL_free(issuer);
}
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
#endif /* WITH_TLS_TRANSP */

static in_port_t get_port(struct sockaddr const *adr) {
	in_port_t res = 0;

	switch (adr->sa_family) {
		case AF_INET:
			res = ((struct sockaddr_in const *)adr)->sin_port;
			break;
		case AF_INET6:
			res = ((struct sockaddr_in6 const *)adr)->sin6_port;
			break;
		default:
			fprintf(stderr, "invalid sa_family %u\n", adr->sa_family);
			exit_code(2, __PRETTY_FUNCTION__, "failed to get port, invalid sa family");
			break;
	}

	return ntohs(res);
}

static sipsak_err resolve(char const *address, unsigned short port, int transport, int family, int binding, struct addrinfo **adrs) {
	struct addrinfo hints;
	int addrinfo_res;

	char port_str[6];

	memset(&hints, 0, sizeof(hints));

	switch (transport) {
		case SIP_UDP_TRANSPORT:
			hints.ai_socktype = SOCK_DGRAM;
			hints.ai_protocol = IPPROTO_UDP;
			break;
		case SIP_TLS_TRANSPORT:
		case SIP_TCP_TRANSPORT:
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_protocol = IPPROTO_TCP;
			break;
	}
	//hints.ai_family = AF_INET;
	hints.ai_family = family;
	hints.ai_flags = binding ? AI_PASSIVE : 0;

	(void)snprintf(port_str, sizeof(port_str), "%hu", port);
	addrinfo_res = getaddrinfo(address, port_str, &hints, adrs);
	return translate_gai_err(addrinfo_res);
}

static sipsak_err adr_to_str(struct sockaddr *adr, int family, char *buf, size_t buf_len, int *ip_type) {
	char const *res;
	switch (family) {
		case AF_INET:
			res = inet_ntop(AF_INET, &((struct sockaddr_in *)adr)->sin_addr, buf, buf_len);
			*ip_type = IPV4;
			break;
		case AF_INET6:
			res = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)adr)->sin6_addr, buf, buf_len);
			*ip_type = IPV6;
			break;
		default:
			return SIPSAK_ERR_UNKNOWN_FAMILY;
	}

	return res ? SIPSAK_ERR_SUCCESS : SIPSAK_ERR_SYS;
}

sipsak_err resolve_str(char const *address, char *buf, size_t buf_len) {
	sipsak_err err = SIPSAK_ERR_SUCCESS;
	struct addrinfo *res;

	int ip_type;

	err = resolve(address, 0, -1, 0, 0, &res);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}

	err = adr_to_str(res->ai_addr, res->ai_family, buf, buf_len, &ip_type);
	freeaddrinfo(res);
	return err;
}

sipsak_err get_local_address_str(struct sipsak_con_data *cd, char *buf, size_t buf_len, int *ip_type) {
	int temp_sock;
	socklen_t adr_size;
	union sipsak_sockaddr adr;

	if (cd->transport == SIP_TLS_TRANSPORT || cd->transport == SIP_TCP_TRANSPORT) {
		adr_size = sizeof(adr);
		if (getsockname(cd->csock, (struct sockaddr *)&adr, &adr_size) < 0) {
			return SIPSAK_ERR_SYS;
		}
		return adr_to_str((struct sockaddr *)&adr, adr.adr.sa_family, buf, buf_len, ip_type);
	}

	temp_sock = socket(cd->to_adr.adr.sa_family, SOCK_DGRAM, IPPROTO_UDP);
	if (temp_sock < 0) {
		return SIPSAK_ERR_SYS;
	}

	if (connect(temp_sock, (struct sockaddr *)&cd->to_adr, cd->to_adr_len) < 0) {
		close(temp_sock);
		return SIPSAK_ERR_SYS;
	}

	adr_size = sizeof(adr);
	if (getsockname(temp_sock, (struct sockaddr *)&adr, &adr_size) < 0) {
		close(temp_sock);
		return SIPSAK_ERR_SYS;
	}
	close(temp_sock);

	return adr_to_str((struct sockaddr *)&adr, cd->from_adr.adr.sa_family, buf, buf_len, ip_type);
}


static sipsak_err get_bound_socket(struct addrinfo *addrs, int *sock, union sipsak_sockaddr *sock_addr, socklen_t *addr_len) {
	struct addrinfo *cur_addr;
	int errno_backup;

	for (cur_addr = addrs; cur_addr; cur_addr = cur_addr->ai_next) {
		*sock = socket(cur_addr->ai_family, cur_addr->ai_socktype, cur_addr->ai_protocol);
		if (*sock < 0) {
			continue;
		}
		if (bind(*sock, cur_addr->ai_addr, cur_addr->ai_addrlen) >= 0) {
			if (sock_addr != NULL) {
				memcpy(sock_addr, cur_addr->ai_addr, cur_addr->ai_addrlen);
			}
			if (addr_len != NULL) {
				*addr_len = cur_addr->ai_addrlen;
			}
			break;
		}
		errno_backup = errno;
		close(*sock);
		errno = errno_backup;
	}
	return cur_addr ? SIPSAK_ERR_SUCCESS : SIPSAK_ERR_NO_IP;
}

static void get_socket_address(int socket, struct sockaddr *adr, socklen_t adr_len) {
	memset(adr, 0, adr_len);
	if (getsockname(socket, adr, &adr_len) < 0) {
		perror("getsockname error");
		exit_code(2, __PRETTY_FUNCTION__, "getsockname error");
	}
}

#ifdef RAW_SUPPORT
static int create_raw_sock(sa_family_t family) {
	int res = 1;
	rawsock = socket(family, SOCK_DGRAM, family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6);
	if (rawsock < 0) {
		if (verbose > 1) {
			fprintf(stderr, "warning: need raw socket (root priviledges) to receive all ICMP errors\n");
		}
		res = 0;
	}
	return res;
}
#endif

static sipsak_err init_network_udp_non_symmetric(struct sipsak_con_data *cd, char const *local_ip) {
	int errno_backup;

	sipsak_err err;

	int created_raw_sock = 0;
	struct addrinfo *res;

	union sipsak_sockaddr listen_adr;

	err = resolve(local_ip, cd->lport, cd->transport, PF_UNSPEC, 1, &res);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}

	err = get_bound_socket(res, &cd->usock, &listen_adr, &cd->from_adr_len);
	if (err != SIPSAK_ERR_SUCCESS) {
		goto err;
	}
	freeaddrinfo(res);
	get_socket_address(cd->usock, (struct sockaddr *)&cd->from_adr, sizeof(cd->from_adr));

#ifdef RAW_SUPPORT
 	created_raw_sock = create_raw_sock(listen_adr.adr.sa_family);
#endif /* RAW_SUPPORT */

	if (!created_raw_sock) {
		/* Rather than PF_UNSPEC, this should probably be listen_adr.adr.family */
		err = resolve(local_ip, 0, cd->transport, PF_UNSPEC, 1, &res);
		if (err != SIPSAK_ERR_SUCCESS) {
			return err;
		}
		err = get_bound_socket(res, &cd->csock, NULL, NULL);
		if (err != SIPSAK_ERR_SUCCESS) {
			goto err;
		}
		freeaddrinfo(res);
	}
	cd->lport = get_port((struct sockaddr *)&cd->from_adr);
	return SIPSAK_ERR_SUCCESS;

err:
	errno_backup = errno;
	freeaddrinfo(res);
	errno = errno_backup;
	return err;
}

static sipsak_err init_network_udp_symmetric(struct sipsak_con_data *cd, char const* local_ip) {
	int errno_backup;

	sipsak_err err;

	struct addrinfo *res;

	union sipsak_sockaddr listen_adr;

	err = resolve(local_ip, cd->lport, cd->transport, PF_UNSPEC, 1, &res);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}

	err = get_bound_socket(res, &cd->csock, &listen_adr, &cd->from_adr_len);
	if (err != SIPSAK_ERR_SUCCESS) {
		goto err;
	}
	freeaddrinfo(res);
	get_socket_address(cd->csock, (struct sockaddr *)&cd->from_adr, sizeof(cd->from_adr));

#ifdef RAW_SUPPORT
	(void)create_raw_sock(listen_adr.adr.sa_family);
#endif /* RAW_SUPPORT */
	cd->lport = get_port((struct sockaddr *)&cd->from_adr);

	return SIPSAK_ERR_SUCCESS;

err:
	errno_backup = errno;
	freeaddrinfo(res);
	errno = errno_backup;
	return err;
}

static sipsak_err init_network_udp(struct sipsak_con_data *cd, char const* local_ip) {
	sipsak_err err;
	if (cd->symmetric) {
		err = init_network_udp_symmetric(cd, local_ip);
	} else {
		err = init_network_udp_non_symmetric(cd, local_ip);
	}
	return err;
}

static sipsak_err init_network_tcp(struct sipsak_con_data *cd, char const *local_ip) {
	int errno_backup;

	sipsak_err err;

	struct addrinfo *res;

	union sipsak_sockaddr listen_adr;

	err = resolve(local_ip, cd->lport, cd->transport, PF_UNSPEC, 1, &res);

	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}
	err = get_bound_socket(res, &cd->csock, &listen_adr, &cd->from_adr_len);
	if (err != SIPSAK_ERR_SUCCESS) {
		goto err;
	}
	freeaddrinfo(res);
	get_socket_address(cd->csock, (struct sockaddr *)&cd->from_adr, sizeof(cd->from_adr));
	cd->lport = get_port((struct sockaddr *)&cd->from_adr);
	return SIPSAK_ERR_SUCCESS;

err:
	errno_backup = errno;
	freeaddrinfo(res);
	errno = errno_backup;
	return err;
}

#ifdef WITH_TLS_TRANSP
static sipsak_err init_network_tls(struct sipsak_con_data *cd, char const *local_ip, char const *ca_file) {
	sipsak_err err;
#ifdef USE_GNUTLS
	tls_session = NULL;
	xcred = NULL;
	gnutls_global_init();
	//gnutls_anon_allocate_client_credentials(&anoncred);
	gnutls_certificate_allocate_credentials(&xcred);
	if (ca_file != NULL) {
		// set the trusted CA file
		gnutls_certificate_set_x509_trust_file(xcred, ca_file, GNUTLS_X509_FMT_PEM);
	}
#else
#ifdef USE_OPENSSL
	ctx = NULL;
	ssl = NULL;
	SSL_library_init();
	SSL_load_error_strings();
#endif
#endif

	err = init_network_tcp(cd, local_ip);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}


#ifdef USE_GNUTLS
	// initialixe the TLS session
	gnutls_init(&tls_session, GNUTLS_CLIENT);
	// use default priorities
	gnutls_set_default_priority(tls_session);
	// put the X509 credentials to the session
	gnutls_credentials_set(tls_session, GNUTLS_CRD_CERTIFICATE, xcred);
	// add the FD to the session
# ifdef HAVE_GNUTLS_319
	gnutls_transport_set_int(tls_session, cd->csock);
# else
	gnutls_transport_set_ptr(tls_session, (gnutls_transport_ptr_t)(intptr_t)cd->csock);
# endif
#else /* USE_GNUTLS */
# ifdef USE_OPENSSL
	create_tls_ctx();
	ssl = SSL_new(ctx);
	if (ssl == NULL) {
		perror("TLS failed to create SSL object");
		exit_code(2, __PRETTY_FUNCTION__, "failed to create SSL object");
	}
	if (SSL_set_fd(ssl, cd->csock) != 1) {
		perror("TLS failed to add socket to SSL object");
		exit_code(2, __PRETTY_FUNCTION__, "failed to add socket to SSL object");
	}
#endif /* USE_OPENSSL */
#endif /* USE_GNUTLS */
	dbg("initialized tls socket %i\n", cd->csock);
	return SIPSAK_ERR_SUCCESS;
}
#endif

sipsak_err init_network(struct sipsak_con_data *cd, char const *local_ip, char const *ca_file) {
	sipsak_err err;

	/*TODO: deal with target_dot and source_dot*/

	/*TODO: deal with raw socket support*/

	switch (cd->transport) {
#ifdef WITH_TLS_TRANSP
		case SIP_TLS_TRANSPORT:
			transport_str = TRANSPORT_TLS_STR;
			err = init_network_tls(cd, local_ip, ca_file);
			break;
#endif
		case SIP_TCP_TRANSPORT:
			transport_str = TRANSPORT_TCP_STR;
			err = init_network_tcp(cd, local_ip);
			break;
		case SIP_UDP_TRANSPORT:
			transport_str = TRANSPORT_UDP_STR;
			err = init_network_udp(cd, local_ip);
			break;
		default:
			err = SIPSAK_ERR_UNKNOWN_SIP_TRANSPORT;
	}

	return err;
}

void shutdown_network() {
# ifdef USE_GNUTLS
  if (tls_session) {
    gnutls_deinit(tls_session);
  }
  if (xcred) {
    gnutls_certificate_free_credentials(xcred);
  }
  gnutls_global_deinit();
# else /* USE_GNUTLS */
#  ifdef USE_OPENSSL
#  endif /* USE_OPENSSL */
# endif /* USE_GNUTLS */
}

#ifdef WITH_TLS_TRANSP
static sipsak_err send_message_tls(char *mes, struct sipsak_con_data *cd) {
	return SIPSAK_ERR_UNKNOWN;
}
#endif /* TLS_TRANSP */

static sipsak_err send_message_plain(char *mes, struct sipsak_con_data *cd) {
	if (cd->csock == -1) {
		dbg("\nusing un-connected socket for sending\n");
		if (sendto(cd->usock, mes, strlen(mes), 0, (struct sockaddr *)&cd->to_adr, cd->to_adr_len) < 0) {
			return SIPSAK_ERR_SEND;
		}
	} else {
		dbg("\nusing connected socket for sending\n");
		if (send(cd->csock, mes, strlen(mes), 0) < 0) {
			return SIPSAK_ERR_SEND;
		}
	}
	return SIPSAK_ERR_SUCCESS;
}

sipsak_err send_message(char *mes, struct sipsak_con_data *cd, struct sipsak_counter *sc, struct sipsak_sr_time *srt) {
	sipsak_err err = SIPSAK_ERR_SUCCESS;

	switch (cd->transport) {
#ifdef WITH_TLS_TRANSP
		case SIP_TLS_TRANSPORT:
			err = send_message_tls(mes, cd);
			break;
#endif
		case SIP_TCP_TRANSPORT:
		case SIP_UDP_TRANSPORT:
			err = send_message_plain(mes, cd);
			break;
	}
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}

	(void)gettimeofday(&srt->sendtime, NULL);
	sc->send_counter++;
	return SIPSAK_ERR_SUCCESS;
}
//void _send_message(char* mes, struct sipsak_con_data *cd,
//			struct sipsak_counter *sc, struct sipsak_sr_time *srt) {
//	struct timezone tz;
//	int ret = -1;
//
//	if (cd->dontsend == 0) {
//		if (verbose > 2) {
//			printf("\nrequest:\n%s", mes);
//		}
//		/* lets fire the request to the server and store when we did */
//		if (cd->csock == -1) {
//			dbg("\nusing un-connected socket for sending\n");
//			ret = sendto(cd->usock, mes, strlen(mes), 0, (struct sockaddr *) &(cd->to_adr), sizeof(struct sockaddr));
//			//ret = sendto(cd->usock, mes, strlen(mes), 0, (struct sockaddr *) &(cd->from_adr), sizeof(struct sockaddr_in));
//		}
//		else {
//			dbg("\nusing connected socket for sending\n");
//#ifdef WITH_TLS_TRANSP
//			if (cd->transport == SIP_TLS_TRANSPORT) {
//# ifdef USE_GNUTLS
//				ret = gnutls_record_send(tls_session, mes, strlen(mes));
//# else /* USE_GNUTLS */
//#  ifdef USE_OPENSSL
//#  endif /* USE_OPENSSL */
//# endif /* USE_GNUTLS */
//			}
//			else {
//#endif /* TLS_TRANSP */
//				ret = send(cd->csock, mes, strlen(mes), 0);
//#ifdef WITH_TLS_TRANSP
//			}
//#endif /* TLS_TRANSP */
//		}
//		(void)gettimeofday(&(srt->sendtime), &tz);
//		if (ret==-1) {
//			if (verbose)
//				printf("\n");
//			perror("send failure");
//			exit_code(2, __PRETTY_FUNCTION__, "send failure");
//		}
//#ifdef HAVE_INET_NTOP
//		if (verbose > 2) {
//			printf("\nsend to: %s:%s:%i\n", transport_str, target_dot, cd->rport);
  //  }
//#endif
//		sc->send_counter++;
//	}
//	else {
//		cd->dontsend = 0;
//	}
//}

void check_socket_error(int socket, char *buffer, int size,
    enum sipsak_modes mode, char *request) {
	struct pollfd sockerr;
	int ret = 0;

	/* lets see if we at least received an icmp error */
	sockerr.fd=socket;
	sockerr.events=POLLERR;
	ret = poll(&sockerr, 1, 10);
	if (ret==1) {
		if (sockerr.revents & POLLERR) {
			recvfrom(socket, buffer, size, 0, NULL, 0);
			if (verbose)
				printf("\n");
			perror("send failure");
			if (mode == SM_RANDTRASH) {
				printf ("last message before send failure:\n%s\n", request);
				log_message(request);
			}
			exit_code(3, __PRETTY_FUNCTION__, "send failure");
		}
	}
}

int check_for_message(char *recv, int size, struct sipsak_con_data *cd,
			struct sipsak_sr_time *srt, struct sipsak_counter *count,
			struct sipsak_delay *sd, enum sipsak_modes mode, int cseq_counter,
      char *request, char *response, int inv_trans) {
	fd_set fd;
	struct timezone tz;
	struct timeval tv;
	double senddiff;
	int ret = 0;

	if (cd->dontrecv == 0) {
		/* set the timeout and wait for a response */
		tv.tv_sec = sd->retryAfter/1000;
		tv.tv_usec = (sd->retryAfter % 1000) * 1000;

		FD_ZERO(&fd);
		if (cd->usock != -1)
			FD_SET(cd->usock, &fd);
		if (cd->csock != -1)
			FD_SET(cd->csock, &fd);
#ifdef RAW_SUPPORT
		if (rawsock != -1)
			FD_SET(rawsock, &fd);
#endif

		ret = select(FD_SETSIZE, &fd, NULL, NULL, &tv);
		(void)gettimeofday(&(srt->recvtime), &tz);
	}
	else {
		cd->dontrecv = 0;
	}

	/* store the time of our first send */
	if (count->send_counter==1) {
		memcpy(&(srt->firstsendt), &(srt->sendtime), sizeof(struct timeval));
	}
	if (sd->retryAfter == srt->timer_t1) {
		memcpy(&(srt->starttime), &(srt->sendtime), sizeof(struct timeval));
	}
	if (ret == 0)
	{
		/* lets see if we at least received an icmp error */
		if (cd->csock == -1) 
			check_socket_error(cd->usock, recv, size, mode, request);
		else
			check_socket_error(cd->csock, recv, size, mode, request);
		/* printout that we did not received anything */
		if (verbose > 0) {
			if (mode == SM_TRACE) {
				printf("%i: timeout after %i ms\n", count->namebeg, sd->retryAfter);
			}
			else if (mode == SM_USRLOC ||
               mode == SM_INVITE ||
               mode == SM_MESSAGE) {
				printf("timeout after %i ms\n", sd->retryAfter);
			}
			else {
				printf("** timeout after %i ms**\n", sd->retryAfter);
			}
		}
		if (mode == SM_RANDTRASH) {
			printf("did not get a response on this request:\n%s\n", request);
			if (cseq_counter < count->nameend) {
				if (count->randretrys == 2) {
					printf("sent the following message three "
							"times without getting a response:\n%s\n"
							"give up further retransmissions...\n", request);
					log_message(request);
					exit_code(3, __PRETTY_FUNCTION__, "too many retransmissions, giving up...");
				}
				else {
					printf("resending it without additional "
							"random changes...\n\n");
					(count->randretrys)++;
				}
			}
		}
		senddiff = deltaT(&(srt->starttime), &(srt->recvtime));
		if (senddiff > (double)srt->timer_final) {
			if (srt->timing == 0) {
				if (verbose>0)
					printf("*** giving up, no final response after %.3f ms\n", senddiff);
				log_message(request);
				exit_code(3, __PRETTY_FUNCTION__, "timeout (no final response)");
			}
			else {
				srt->timing--;
				count->run++;
				sd->all_delay += senddiff;
				sd->big_delay = senddiff;
				new_transaction(request, response);
				sd->retryAfter = srt->timer_t1;
				if (srt->timing == 0) {
					printf("%.3f/%.3f/%.3f ms\n", sd->small_delay, sd->all_delay / count->run, sd->big_delay);
					log_message(request);
					exit_code(3, __PRETTY_FUNCTION__, "timeout (no final response)");
				}
			}
		}
		else {
			/* set retry time according to RFC3261 */
			if ((inv_trans) || (sd->retryAfter *2 < srt->timer_t2)) {
				sd->retryAfter = sd->retryAfter * 2;
			}
			else {
				sd->retryAfter = srt->timer_t2;
			}
		}
		(count->retrans_s_c)++;
		if (srt->delaytime.tv_sec == 0)
			memcpy(&(srt->delaytime), &(srt->sendtime), sizeof(struct timeval));
		/* if we did not exit until here lets try another send */
		return -1;
	}
	else if ( ret == -1 ) {
		perror("select error");
		exit_code(2, __PRETTY_FUNCTION__, "internal select error");
	}
	else if (((cd->usock != -1) && FD_ISSET(cd->usock, &fd)) || ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))) {
		if ((cd->usock != -1) && FD_ISSET(cd->usock, &fd))
			ret = cd->usock;
		else if ((cd->csock != -1) && FD_ISSET(cd->csock, &fd))
			ret = cd->csock;
		else {
			printf("unable to determine the socket which received something\n");
			exit_code(2, __PRETTY_FUNCTION__, "failed to determine receiving socket");
		}
		/* no timeout, no error ... something has happened :-) */
		if ((mode == SM_FLOOD || mode == SM_UNDEFINED) && (verbose > 1))
			printf ("\nmessage received\n");
	}
#ifdef RAW_SUPPORT
	else if ((rawsock != -1) && FD_ISSET(rawsock, &fd)) {
		if (verbose > 1)
			//printf("\nreceived ICMP message");
		ret = rawsock;
	}
#endif
	else {
		printf("\nselect returned successfully, nothing received\n");
		return -1;
	}
	return ret;
}

struct sipsak_address const *get_cur_address(struct sipsak_con_data *cd) {
	return cd->cur_address == (size_t)-1 || cd->cur_address >= cd->num_addresses ? NULL : &cd->addresses[cd->cur_address];
}

void set_addresses(struct sipsak_con_data *cd, struct sipsak_address *addresses, size_t num_addresses) {
	destroy_sipsak_addresses(cd->addresses, cd->num_addresses);
	cd->addresses = addresses;
	cd->num_addresses = num_addresses;
	cd->cur_address = -1;
}

int complete_mes(char *mes, int size) {
	int cl = 0, headers = 0, len = 0;
	char *tmp = NULL;

	cl = get_cl(mes);
	dbg("CL: %i\n", cl);
	if (cl < 0){
		if (verbose > 0)
			printf("missing CL header; waiting for more bytes...\n");
		return 0;
	}
	tmp = get_body(mes);
	dbg("body: '%s'\n", tmp);
	headers = tmp - mes;
	dbg("length: %i, headers: %i\n", size, headers);
	len = headers + cl;
	if (len == size) {
		if (verbose > 0)
			printf("message is complete\n");
		return 1;
	}
	else if (len > size) {
		if (verbose > 0)
			printf("waiting for more bytes...\n");
		return 0;
	}
	else {
		/* we received more then the sender claims to sent
		 * for now we treat this as a complete message
		 * FIXME: should we store the extra bytes in a buffer and
		 *        truncate the message at the calculated length !? */
		if (verbose > 0)
			printf("received too much bytes...\n");
		return 1;
	}
}

static sipsak_err icmp6_extract(unsigned char const *buf, size_t buf_len, struct sipsak_con_data *cd) {
	unsigned int icmp_type, icmp_code;
	unsigned int udp_dst_p, udp_src_p;
	unsigned int protocol;
	size_t internal_ip_buf_len;
	size_t udp_buf_len;
	unsigned char const *internal_ip_buf, *udp_buf;

	if (icmp6_type(buf, buf_len, &icmp_type) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	switch (icmp_type) {
		case ICMP6_DESTINATION_UNREACHABLE:
		case ICMP6_PACKET_TOO_BIG:
		case ICMP6_TIME_EXCEEDED:
		case ICMP6_PARAMETER_PROBLEM:
			break;
		default:
			return SIPSAK_ERR_ICMP_UNOWNED;
	}

	if (icmp6_code(buf, buf_len, &icmp_code) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (icmp6_ip_header(buf, buf_len, &internal_ip_buf_len, &internal_ip_buf) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (ipv6_next_header(internal_ip_buf, internal_ip_buf_len, &protocol) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (protocol != IPPROTO_UDP) {
		return SIPSAK_ERR_ICMP_UNOWNED_PROTO;
	}

	if (ipv6_next_payload(internal_ip_buf, internal_ip_buf_len, &udp_buf_len, &udp_buf) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (udp_dst_port(udp_buf, udp_buf_len, &udp_dst_p) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}
	if (udp_src_port(udp_buf, udp_buf_len, &udp_src_p) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (udp_src_p != cd->lport || udp_dst_p != cd->rport) {
		return SIPSAK_ERR_ICMP_UNOWNED_PORT;
	}

	cd->last_icmp_code = icmp_code;
	cd->last_icmp_type = icmp_type;

	return SIPSAK_ERR_ICMP6;

}

static sipsak_err icmp4_extract(unsigned char const *buf, size_t buf_len, struct sipsak_con_data *cd) {
	size_t internal_ip_buf_len;
	unsigned int protocol, ihl;
	unsigned int icmp_type, icmp_code;
	unsigned int ip_header_len, icmp_buf_len, internal_ip_header_len, udp_buf_len;
	unsigned int  udp_src_p, udp_dst_p;
	unsigned char const *icmp_buf, *internal_ip_buf, *udp_buf;

	if (ipv4_ihl(buf, buf_len, &ihl) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}
	
	ip_header_len = ihl*4;
	if (buf_len < ip_header_len) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	icmp_buf_len = buf_len - ip_header_len;
	icmp_buf = buf + ip_header_len;

	if (icmp4_type(icmp_buf, icmp_buf_len, &icmp_type) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	switch (icmp_type) {
		case ICMP4_DESTINATION_UNREACHABLE:
		case ICMP4_REDIRECT:
		case ICMP4_TIME_EXCEEDED:
		case ICMP4_PARAMETER_PROBLEM:
			break;
		default:
			return SIPSAK_ERR_ICMP_UNOWNED_TYPE;
	}

	if (icmp4_code(icmp_buf, icmp_buf_len, &icmp_code) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (icmp4_ip_header(icmp_buf, icmp_buf_len, &internal_ip_buf_len, &internal_ip_buf) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (ipv4_protocol(internal_ip_buf, internal_ip_buf_len, &protocol) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}
	if (protocol != IPPROTO_UDP) {
		return SIPSAK_ERR_ICMP_UNOWNED_PROTO;
	}

	if (ipv4_ihl(internal_ip_buf, internal_ip_buf_len, &ihl) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	internal_ip_header_len = ihl*4;

	if (internal_ip_buf_len < internal_ip_header_len) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	udp_buf_len = internal_ip_buf_len - internal_ip_header_len;
	udp_buf = internal_ip_buf + internal_ip_header_len;

	if (udp_src_port(udp_buf, udp_buf_len, &udp_src_p) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (udp_dst_port(udp_buf, udp_buf_len, &udp_dst_p) < 0) {
		return SIPSAK_ERR_RAWBUF_SIZE;
	}

	if (udp_src_p != cd->lport || udp_dst_p != cd->rport) {
		return SIPSAK_ERR_ICMP_UNOWNED_PORT;
	}

	cd->last_icmp_type = icmp_type;
	cd->last_icmp_code = icmp_code;

	return SIPSAK_ERR_ICMP4;
}

void get_last_icmp(struct sipsak_con_data *cd, unsigned int *icmp_type, unsigned int *icmp_code) {
	*icmp_type = (unsigned int)cd->last_icmp_type;
	*icmp_code = (unsigned int)cd->last_icmp_code;
}

static sipsak_err handle_raw_socket(struct sipsak_con_data *cd) {
	union sipsak_sockaddr fadr = {0};
	socklen_t flen = sizeof(fadr);
	ssize_t recv_ret;

	unsigned char buf[RAW_HEADER_MAXLEN];

	recv_ret = recvfrom(rawsock, buf, sizeof(buf), 0, (struct sockaddr *)&fadr, &flen);
	if (recv_ret < 0) {
		return SIPSAK_ERR_SYS;
	}

	switch (cd->to_adr.adr.sa_family) {
		case AF_INET:
			return icmp4_extract(buf, recv_ret, cd);
		case AF_INET6:
			return icmp6_extract(buf, recv_ret, cd);
		default:
			return SIPSAK_ERR_UNKNOWN;
	}
}

sipsak_err recv_message(char *buf, size_t buf_size, int inv_trans, struct sipsak_delay *sd, struct sipsak_sr_time *srt, struct sipsak_counter *count, struct sipsak_con_data *cd, struct sipsak_regexp *reg, enum sipsak_modes mode, int cseq_counter, char *request, char *response, size_t *num_read) {
	int sock = 0;
	int recv_ret;
	double tmp_delay;
	union sipsak_sockaddr fadr;

	*num_read = 0;

	sock = check_for_message(buf, buf_size, cd, srt, count, sd, mode, cseq_counter, request, response, inv_trans);
	if (sock <= 1) {
		return SIPSAK_ERR_AGAIN;
	}

#ifdef RAW_SUPPORT

	if (sock == rawsock) {
		return handle_raw_socket(cd);
	}

#endif

	switch (cd->transport) {
#ifdef WITH_TLS_TRANSP
		case SIP_TLS_TRANSPORT:
			abort();
#endif
		case SIP_TCP_TRANSPORT:
		case SIP_UDP_TRANSPORT:
			recv_ret = recvfrom(sock, buf, buf_size, 0, NULL, 0);
			break;
	}

	if (recv_ret < 0) {
		return SIPSAK_ERR_SYS;
	}

	buf[recv_ret] = '\0';

	*num_read = recv_ret;

	/* store the biggest delay if one occurred */
	if (srt->delaytime.tv_sec != 0) {
		tmp_delay = deltaT(&(srt->delaytime), &(srt->recvtime));
		if (tmp_delay > sd->big_delay)
			sd->big_delay = tmp_delay;
		if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay))
				sd->small_delay = tmp_delay;
			srt->delaytime.tv_sec = 0;
			srt->delaytime.tv_usec = 0;
		}
		if (srt->timing > 0) {
			tmp_delay = deltaT(&(srt->sendtime), &(srt->recvtime));
			if (tmp_delay > sd->big_delay) {
				sd->big_delay = tmp_delay;
			}
			if ((sd->small_delay == 0) || (tmp_delay < sd->small_delay)) {
				sd->small_delay = tmp_delay;
			}
			sd->all_delay += tmp_delay;
		}

	if (cd->transport != SIP_UDP_TRANSPORT) {
		if (!complete_mes(buf, recv_ret)) {
			return SIPSAK_ERR_AGAIN;
		}
	}
	return SIPSAK_ERR_SUCCESS;
}

char const *get_target_dot(struct sipsak_con_data *cd) {
	return target_dot;
}

static void set_target_dot(union sipsak_sockaddr *adr) {
	inet_ntop(adr->adr.sa_family, (struct sockaddr *)adr, target_dot, sizeof(target_dot));
}

#ifdef WITH_TLS_TRANSP
# ifdef USE_OPENSSL
static int set_target_with_openssl(struct sipsak_con_data *con, char *domainname, int connect_csock, int ignore_ca_fail) {
	int ret;
	int err;
	X509* cert;

	ret = SSL_connect(ssl);
	if (ret == 1) {
		dbg("TLS connect successful\n");
		if (verbose > 2) {
			printf("TLS connect: new connection using %s %s %d\n",
			SSL_get_cipher_version(ssl), SSL_get_cipher_name(ssl),
			SSL_get_cipher_bits(ssl, 0));
		}
		cert = SSL_get_peer_certificate(ssl);
		if (cert != 0) {
			tls_dump_cert_info("TLS connect: server certificate", cert);
			if (SSL_get_verify_result(ssl) != X509_V_OK) {
				perror("TLS connect: server certificate verification failed!!!\n");
				exit_code(3, __PRETTY_FUNCTION__, "TLS server certificate verification falied");
			}
			X509_free(cert);
		}
		else {
			perror("TLS connect: server did not present a certificate\n");
			exit_code(3, __PRETTY_FUNCTION__, "missing TLS server certificate");
		}
	}
	else {
		err = SSL_get_error(ssl, ret);
		switch (err) {
			case SSL_ERROR_ZERO_RETURN:
				perror("TLS handshake failed cleanly'n");
				break;
			case SSL_ERROR_WANT_READ:
				perror("Need to get more data to finish TLS connect\n");
				break;
			case SSL_ERROR_WANT_WRITE:
				perror("Need to send more data to finish TLS connect\n");
				break;
#if OPENSSL_VERSION_NUMBER >= 0x00907000L /* 0.9.7 */
			case SSL_ERROR_WANT_CONNECT:
				perror("Need to retry connect\n");
				break;
			case SSL_ERROR_WANT_ACCEPT:
				perror("Need to retry accept'n");
				break;
#endif /* 0.9.7 */
			case SSL_ERROR_WANT_X509_LOOKUP:
				perror("Application callback asked to be called again\n");
				break;
			case SSL_ERROR_SYSCALL:
				printf("TLS connect: %d\n", err);
				if (!err) {
					if (ret == 0) {
						perror("Unexpected EOF occurred while performing TLS connect\n");
					}
					else {
						printf("IO error: (%d) %s\n", errno, strerror(errno));
					}
				}
				break;
			default:
				printf("TLS error: %d\n", err);
		}
		exit_code(2, __PRETTY_FUNCTION__, "generic SSL error");
	}
	return 1;
}
# endif /* USE_OPENSSL */

# ifdef USE_GNUTLS
static int set_target_with_gnutls(char *domainname, int ignore_ca_fail) {
	int ret;
#  ifdef HAVE_GNUTLS_319
	gnutls_handshake_set_timeout(tls_session, GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT);
#  endif
	ret = gnutls_handshake(tls_session);
	if (ret < 0) {
		dbg("TLS Handshake FAILED!!!\n");
		gnutls_perror(ret);
		exit_code(3, __PRETTY_FUNCTION__, "TLS handshake failed");
	}
	else if (verbose > 2) {
		dbg(" TLS Handshake was completed!\n");
		gnutls_session_info(tls_session);
		if (verify_certificate_simple(tls_session, domainname, ignore_ca_fail) != 0) {
			if (ignore_ca_fail == 1) {
				if (verbose) {
					printf("WARN: Ignoring verification failures of the server certificate\n");
				}
			} else {
				if (verbose > 1) {
					printf("TLS server certificate verification can be ignored with option --tls-ignore-cert-failure.\n");
				}
				exit_code(3, __PRETTY_FUNCTION__, "failure during TLS server certificate verification");
			}
		}
		//verify_certificate_chain(tls_session, domainname, cert_chain, cert_chain_length);
	}
	return 1;
}
# endif /* USE_GNUTLS */

#endif /* WITH_TLS_TANSP */

static sipsak_err set_target_with_tls(char const *domainname, int ignore_ca_fail) {
# ifdef USE_OPENSSL
	return set_target_with_openssl(domainname, ignore_ca_fail);
# else
#ifdef USE_GNUTLS
	return set_target_with_gnutls(domainname, ignore_ca_fail);
#endif /* USE_GNUTLS */
#endif
}

static sipsak_err connect_socket(int sock, struct addrinfo *addrs, union sipsak_sockaddr *to_adr, socklen_t *to_adr_len) {
	sipsak_err err = SIPSAK_ERR_SUCCESS;
	struct addrinfo *cur_addr;
	for (cur_addr = addrs; cur_addr; cur_addr = cur_addr->ai_next) {
		if (connect(sock, cur_addr->ai_addr, cur_addr->ai_addrlen) >= 0) {
			break;
		}
	}
	if (cur_addr == NULL) {
		err = SIPSAK_ERR_NO_IP;
	}
	memcpy(to_adr, cur_addr->ai_addr, cur_addr->ai_addrlen);
	*to_adr_len = cur_addr->ai_addrlen;
	return err;
}

static sipsak_err rebind_stream_csock(struct sipsak_con_data *cd) {
	int errno_backup;

	int optval = 1;

	union sipsak_sockaddr sockname = {0};
	socklen_t sockname_len = sizeof(sockname);

	if (getsockname(cd->csock, (struct sockaddr *)&sockname, &sockname_len) < 0) {
		goto err;
	}

	(void)shutdown(cd->csock, SHUT_RDWR);
	close(cd->csock);

	cd->csock = socket(sockname.adr.sa_family, SOCK_STREAM, IPPROTO_TCP);
	if (cd->csock < 0) {
		goto err;
	}

	setsockopt(cd->csock, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	if (bind(cd->csock, (struct sockaddr *)&sockname, sockname_len) < 0) {
		goto bind_err;

	}
	return SIPSAK_ERR_SUCCESS;

bind_err:
	errno_backup = errno;
	close(cd->csock);
	cd->csock = -1;
	errno = errno_backup;
err:
	return SIPSAK_ERR_REBIND_TCP;
}

static sipsak_err set_target_udp(struct sipsak_con_data *cd) {
	struct sipsak_address *cur_target;

	int errno_backup;
	sipsak_err err;

	struct addrinfo *res;


	memset(&cd->to_adr, 0, sizeof(cd->to_adr));

	cur_target = &cd->addresses[++cd->cur_address];

	err = resolve(cur_target->address, cur_target->port, cd->transport, cd->from_adr.adr.sa_family, 0, &res);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}

	if (cd->csock != -1) {
		err = connect_socket(cd->csock, res, &cd->to_adr, &cd->to_adr_len);
		if (err != SIPSAK_ERR_SUCCESS) {
			goto err;
		}
	} else {
		memcpy(&cd->to_adr, res->ai_addr, res->ai_addrlen);
		cd->to_adr_len = res->ai_addrlen;
	}
	freeaddrinfo(res);
	cd->connected = 1;
	set_target_dot(&cd->to_adr);
	cd->rport = get_port((struct sockaddr *)&cd->to_adr);
	return SIPSAK_ERR_SUCCESS;

err:
	errno_backup = errno;
	freeaddrinfo(res);
	errno = errno_backup;
	return err;
}

static sipsak_err set_target_tcp(struct sipsak_con_data *cd) {
	struct sipsak_address *cur_target;

	int errno_backup;
	sipsak_err err;

	struct addrinfo *res;

	if (cd->connected) {
		err = rebind_stream_csock(cd);
		if (err != SIPSAK_ERR_SUCCESS) {
			return err;
		}
	}
	cur_target = &cd->addresses[++cd->cur_address];
	err = resolve(cur_target->address, cur_target->port, cd->transport, cd->from_adr.adr.sa_family, 0, &res);
	if (err != SIPSAK_ERR_SUCCESS) {
		return err;
	}
	err = connect_socket(cd->csock, res, &cd->to_adr, &cd->to_adr_len);
	if (err != SIPSAK_ERR_SUCCESS) {
		goto err;
	}
	freeaddrinfo(res);
	cd->connected = 1;
	set_target_dot(&cd->to_adr);
	cd->rport = get_port((struct sockaddr *)&cd->to_adr);
	return SIPSAK_ERR_SUCCESS;

err:
	errno_backup = errno;
	freeaddrinfo(res);
	errno = errno_backup;
	return err;
}

#ifdef WITH_TLS_TRANSP
static sipsak_err set_target_tls(struct sipsak_con_data *cd, char const *domainname, int ignore_ca_fail) {
	int res;
	res = set_target_tcp(cd);
	if (res < 0) return res;

	return set_target_with_tls(domainname, ignore_ca_fail);
}
#endif /* WITH_TLS_TRANSP */

sipsak_err set_target(struct sipsak_con_data *cd, char const *domainname, int ignore_ca_fail) {
	if (cd->cur_address + 1 >= cd->num_addresses) {
		return SIPSAK_ERR_EOF;
	}
	switch (cd->transport) {
		case SIP_UDP_TRANSPORT:
			return set_target_udp(cd);
		case SIP_TCP_TRANSPORT:
			return set_target_tcp(cd);
#ifdef WITH_TLS_TRANSP
		/*case SIP_TLS_TRANSPORT:
			return set_target_tls(cd, domainname, ignore_ca_fail); */
#endif /* WITH_TLS_TRANSP */
	}
	return SIPSAK_ERR_SUCCESS;
}
