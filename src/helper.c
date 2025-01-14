/*
 * Copyright (C) 2002-2004 Fhg Fokus
 * Copyright (C) 2004-2022 Nils Ohlmeier
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

#ifdef HAVE_STDARG_H
# include <stdarg.h>
#endif
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif
#ifdef HAVE_UNISTD_H
# ifdef HAVE_SYS_TYPES_H
#  include <sys/types.h>
# endif
# include <unistd.h>
#endif
#ifdef HAVE_SYS_UTSNAME_H
# include <sys/utsname.h>
#endif
#ifdef HAVE_CTYPE_H
# include <ctype.h>
#endif
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
#ifdef HAVE_ERRNO_H
# include <errno.h>
#endif
#ifdef HAVE_CARES_H
# ifdef HAVE_ARPA_NAMESER_H
#  include <arpa/nameser.h>
# endif
# include <ares.h>
# ifndef NS_RRFIXEDSZ
#  define NS_RRFIXEDSZ 10
#  define NS_QFIXEDSZ  4
#  define NS_HFIXEDSZ  12
# endif
 int caport;
 unsigned long caadr;
 int capriority;
 char *ca_tmpname;
 ares_channel channel;

#endif // HAVE_CARES_H

#include "helper.h"
#include "exit_code.h"
#include "error.h"

#if defined(RUNNING_CHECK) && !defined(HAVE_CHECK_H)
  #error Missing check unit test framework!
#endif


char const *ip_to_str(struct sockaddr *adr, char *buf, size_t buf_len) {
	char const *res;
	switch (adr->sa_family) {
		case AF_INET:
			res = inet_ntop(AF_INET, &((struct sockaddr_in *)adr)->sin_addr, buf, buf_len);
			break;
		case AF_INET6:
			res = inet_ntop(AF_INET6, &((struct sockaddr_in6 *)adr)->sin6_addr, buf, buf_len);
			break;
	}

	return res;
}

/* returns 1 if the string is an IP address, otherwise zero */
int is_ip(char const *str) {
	struct in_addr addr4;
	struct in6_addr addr6;
	int result;
	result = inet_pton(AF_INET, str, &addr4);
	if (result == 1) return 1;
	result = inet_pton(AF_INET6, str, &addr6);
	return result == 1;
}

/*int is_ip(char *str) {
	int octet = 0;

	while (*str) {
		int digits = 0, value = 0;
		while (isdigit(*str) && digits <= 3) {
			value = (value * 10) + (*str - '0');
			digits++;
			str++;
		}
		if (digits < 1 || digits > 3 || value > 255)
			return 0;
		octet++;
		if (*str != '.')
			break;
		str++;
	}

	return (*str == '\0' && octet == 4) ? 1 : 0;
}*/

/* take either a dot.decimal string of ip address or a 
domain name and returns a NETWORK ordered long int containing
the address. I chose to internally represent the address as long for speedier
comparisons.

any changes to getaddress have to be patched back to the net library.
contact: farhan@hotfoon.com

  returns zero if there is an error.
  this is convenient as 0 means 'this' host and the traffic of
  a badly behaving dns system remains inside (you send to 0.0.0.0)
*/
unsigned long getaddress(char *host) {
	struct hostent* pent;
	long addr;

	if (strlen(host) == 0) {
		return 0;
	}
	if (is_ip(host)) {
		return inet_addr(host);
	}

	/* try the system's own resolution mechanism for dns lookup:
	 required only for domain names.
	 in spite of what the rfc2543 :D Using SRV DNS Records recommends,
	 we are leaving it to the operating system to do the name caching.

	 this is an important implementational issue especially in the light
	 dynamic dns servers like dynip.com or dyndns.com where a dial
	 ip address is dynamically assigned a sub domain like farhan.dynip.com

	 although expensive, this is a must to allow OS to take
	 the decision to expire the DNS records as it deems fit.
	*/
	pent = gethostbyname(host);
	if (!pent) {
		printf("'%s' is unresolvable\n", host);
		exit_code(2, __PRETTY_FUNCTION__, "hostname is not resolvable");
	}
	addr = *(uint32_t *) (pent->h_addr);
	return addr;
}

#ifdef HAVE_CARES_H
static const unsigned char *parse_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	char *name;
	long len;
	int status, type, dnsclass, dlen;
	struct in_addr addr;

	if (aptr == NULL) {
		return NULL;
	}
	dbg("ca_tmpname: %s\n", ca_tmpname);
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	if (status != ARES_SUCCESS) {
		printf("error: failed to expand query name\n");
		exit_code(2, __PRETTY_FUNCTION__, "failed to expand query name");
	}
	aptr += len;
	if (aptr + NS_RRFIXEDSZ > abuf + alen) {
		printf("error: not enough data in DNS answer 1\n");
		free(name);
		return NULL;
	}
	type = DNS_RR_TYPE(aptr);
	dnsclass = DNS_RR_CLASS(aptr);
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	if (aptr + dlen > abuf + alen) {
		printf("error: not enough data in DNS answer 2\n");
		free(name);
		return NULL;
	}
	if (dnsclass != CARES_CLASS_C_IN) {
		printf("error: unsupported dnsclass (%i) in DNS answer\n", dnsclass);
		free(name);
		return NULL;
	}
	if (type != CARES_TYPE_SRV && type != CARES_TYPE_A && type != CARES_TYPE_CNAME) {
		printf("error: unsupported DNS response type (%i)\n", type);
		free(name);
		return NULL;
	}
	if (type == CARES_TYPE_SRV) {
		free(name);
		int priority = DNS__16BIT(aptr);
		dbg("Processing SRV record with priority %d\n", priority);
		if (capriority == -1 || priority < capriority) {
			capriority = priority;
			caport = DNS__16BIT(aptr + 4);
			dbg("caport: %i\n", caport);
			status = ares_expand_name(aptr + 6, abuf, alen, &name, &len);
			if (status != ARES_SUCCESS) {
				printf("error: failed to expand SRV name\n");
				return NULL;
			}
			dbg("SRV name: %s\n", name);
			if (is_ip(name)) {
				caadr = inet_addr(name);
				free(name);
			}
			else {
				if (ca_tmpname) {
					free(ca_tmpname);
				}
				ca_tmpname = name;
			}
		}
	}
	else if (type == CARES_TYPE_CNAME) {
		if ((ca_tmpname != NULL) &&
				(STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0)) {
			if (ca_tmpname) {
				free(ca_tmpname);
			}
			ca_tmpname = malloc(strlen(name) + 1);
			if (ca_tmpname == NULL) {
				printf("error: failed to allocate memory\n");
				exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
			}
			strcpy(ca_tmpname, name);
			free(name);
		}
		else {
			free(name);
			status = ares_expand_name(aptr, abuf, alen, &name, &len);
			if (status != ARES_SUCCESS) {
				printf("error: failed to expand CNAME\n");
				return NULL;
			}
			dbg("CNAME: %s\n", name);
			if (is_ip(name)) {
				caadr = inet_addr(name);
				free(name);
			}
			else {
				if (ca_tmpname) {
					free(ca_tmpname);
				}
				ca_tmpname = name;
			}
		}
	}
	else if (type == CARES_TYPE_A) {
		if (dlen == 4 && STRNCASECMP(ca_tmpname, name, strlen(ca_tmpname)) == 0) {
			memcpy(&addr, aptr, sizeof(struct in_addr));
			caadr = addr.s_addr;
		}
		free(name);
	}
	return aptr + dlen;
}

static const unsigned char *skip_rr(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status, dlen;
	long len;
	char *name;

	if (aptr == NULL) {
		return NULL;
	}
	dbg("skipping rr section...\n");
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	if (status != ARES_SUCCESS) {
		return NULL;
	}
	aptr += len;
	dlen = DNS_RR_LEN(aptr);
	aptr += NS_RRFIXEDSZ;
	aptr += dlen;
	free(name);
	return aptr;
}

static const unsigned char *skip_query(const unsigned char *aptr, const unsigned char *abuf, int alen) {
	int status;
	long len;
	char *name;

	if (aptr == NULL) {
		return NULL;
	}
	dbg("skipping query section...\n");
	status = ares_expand_name(aptr, abuf, alen, &name, &len);
	if (status != ARES_SUCCESS) {
		return NULL;
	}
	aptr += len;
	aptr += NS_QFIXEDSZ;
	free(name);
	return aptr;
}

static void cares_callback(void *arg, int status, int timeouts, unsigned char *abuf, int alen) {
	int i;
	unsigned int ancount, nscount, arcount;
	const unsigned char *aptr;

	dbg("cares_callback: status=%i, alen=%i\n", status, alen);
	if (status != ARES_SUCCESS) {
		if (verbose > 1)
			printf("ares failed: %s\n", ares_strerror(status));
		return;
	}

	ancount = DNS_HEADER_ANCOUNT(abuf);
	nscount = DNS_HEADER_NSCOUNT(abuf);
	arcount = DNS_HEADER_ARCOUNT(abuf);

	dbg("ancount: %i, nscount: %i, arcount: %i\n", ancount, nscount, arcount);

	/* safety check */
	if (alen < NS_HFIXEDSZ)
		return;
	aptr = abuf + NS_HFIXEDSZ;

	aptr = skip_query(aptr, abuf, alen);
	if (aptr == NULL) {
		return;
	}

	for (i = 0; i < ancount && aptr != NULL; i++) {
		aptr = parse_rr(aptr, abuf, alen);
	}
	if (caadr == 0 && aptr != NULL) {
		for (i = 0; i < nscount && aptr != NULL; i++) {
			aptr = skip_rr(aptr, abuf, alen);
		}
		for (i = 0; i < arcount && aptr != NULL; i++) {
			aptr = parse_rr(aptr, abuf, alen);
		}
	}
}

static inline unsigned long srv_ares(char *host, int *port, char *srv) {
	int nfds, count, srvh_len;
	char *srvh;
	fd_set read_fds, write_fds;
	struct timeval *tvp, tv;

	caport = 0;
	caadr = 0;
	capriority = -1;
	ca_tmpname = NULL;
	dbg("starting ARES query\n");

	srvh_len = strlen(host) + strlen(srv) + 2;
	srvh = malloc(srvh_len);
	if (srvh == NULL) {
		printf("error: failed to allocate memory (%i) for ares query\n", srvh_len);
		exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
	}
	memset(srvh, 0, srvh_len);
	strncpy(srvh, srv, strlen(srv));
	memcpy(srvh + strlen(srv), ".", 1);
	strcpy(srvh + strlen(srv) + 1, host);
	dbg("hostname: '%s', len: %i\n", srvh, srvh_len);

	ares_query(channel, srvh, CARES_CLASS_C_IN, CARES_TYPE_SRV, cares_callback, (char *) NULL);
	dbg("ares_query finished, waiting for result...\n");
	/* wait for query to complete */
	while (1) {
		FD_ZERO(&read_fds);
		FD_ZERO(&write_fds);
		nfds = ares_fds(channel, &read_fds, &write_fds);
		if (nfds == 0)
			break;
		tvp = ares_timeout(channel, NULL, &tv);
		count = select(nfds, &read_fds, &write_fds, NULL, tvp);
		if (count < 0 && errno != EINVAL) {
			perror("ares select");
			exit_code(2, __PRETTY_FUNCTION__, "ares DNS resolution failure");
		}
		ares_process(channel, &read_fds, &write_fds);
	}
	dbg("ARES answer processed\n");
	*port = caport;
	if (caadr == 0 && ca_tmpname != NULL) {
		caadr = getaddress(ca_tmpname);
	}
	if (ca_tmpname != NULL)
		free(ca_tmpname);
	free(srvh);
	return caadr;
}
#endif // HAVE_CARES_H

unsigned long getsrvaddress(char *host, int *port, char *srv) {
#ifdef HAVE_CARES_H
	return srv_ares(host, port, srv);
#else // HAVE_CARES_H
	return 0;
#endif
}

/* Finds the SRV records for the given host. It returns the target IP
 * address and fills the port and transport if a suitable SRV record
 * exists. Otherwise it returns 0. The function follows 3263: first
 * TLS, then TCP and finally UDP. */
unsigned long getsrvadr(char *host, int *port, unsigned int *transport) {
	unsigned long adr = 0;

#ifdef HAVE_SRV
	int srvport = 5060;

#ifdef HAVE_CARES_H
	int status;
	int optmask = ARES_OPT_FLAGS;
	struct ares_options options;

	options.flags = ARES_FLAG_NOCHECKRESP;
	options.servers = NULL;
	options.nservers = 0;

	status = ares_init_options(&channel, &options, optmask);
	if (status != ARES_SUCCESS) {
		printf("error: failed to initialize ares\n");
		exit_code(2, __PRETTY_FUNCTION__, "failed to init ares lib");
	}
#endif

#ifdef WITH_TLS_TRANSP
	adr = getsrvaddress(host, &srvport, SRV_SIP_TLS);
	if (adr != 0) {
		*transport = SIP_TLS_TRANSPORT;
		if (verbose > 1)
			printf("using SRV record: %s.%s:%i\n", SRV_SIP_TLS, host, srvport);
	}
	else {
#endif
		adr = getsrvaddress(host, &srvport, SRV_SIP_TCP);
		if (adr != 0) {
			*transport = SIP_TCP_TRANSPORT;
			if (verbose > 1)
				printf("using SRV record: %s.%s:%i\n", SRV_SIP_TCP, host, srvport);
		}
		else {
			adr = getsrvaddress(host, &srvport, SRV_SIP_UDP);
			if (adr != 0) {
				*transport = SIP_UDP_TRANSPORT;
				if (verbose > 1)
					printf("using SRV record: %s.%s:%i\n", SRV_SIP_UDP, host, srvport);
			}
		}
#ifdef WITH_TLS_TRANSP
	}
#endif

#ifdef HAVE_CARES_H
	ares_destroy(channel);
#endif

	*port = srvport;
#endif // HAVE_SRV
	return adr;
}
/* because the full qualified domain name is needed by many other
   functions it will be determined by this function.
*/
sipsak_err get_fqdn(char *buf, size_t buf_len) {
	char hname[100], dname[100];
	size_t namelen = 100;
	struct utsname un;
	if ((uname(&un)) == 0) {
		strncpy(hname, un.nodename, sizeof(hname) - 1);
	} else {
		if (gethostname(hname, namelen) < 0) {
			return SIPSAK_ERR_SYS;
		}
	}
#ifdef HAVE_GETHOSTNAME
	if (strchr(hname, '.') == NULL) {
		if (getdomainname(dname, namelen) < 0) {
			return SIPSAK_ERR_SYS;
		}
		if (strcmp(dname, "(none)") != 0) {
			snprintf(buf, FQDN_SIZE, "%s.%s", hname, dname);
		}
	} else {
		strncpy(buf, hname, FQDN_SIZE - 1);
	}
#endif

	if (strchr(buf, '.') == NULL) {
		return SIPSAK_ERR_INVAL_DOMAIN;
	}

	return SIPSAK_ERR_SUCCESS;
}

/* this function searches for search in mess and replaces it with
   replacement */
void replace_string(char *mess, char *search, char *replacement) {
	char *backup, *insert;

	insert=STRCASESTR(mess, search);
	if (insert==NULL){
		if (verbose > 2)
			fprintf(stderr, "warning: could not find this '%s' replacement string in "
					"message\n", search);
	}
	else {
		while (insert){
			backup=str_alloc(strlen(insert)+1);
			strcpy(backup, insert+strlen(search));
			strcpy(insert, replacement);
			strcpy(insert+strlen(replacement), backup);
			free(backup);
			insert=STRCASESTR(mess, search);
		}
	}
}

/* checks if the strings contains special double marks and then
 * replace all occurrences of this strings in the message */
void replace_strings(char *mes, char *strings) {
	char *pos, *atr, *val, *repl, *end;
	char sep;

	pos=atr=val=repl = NULL;
	dbg("replace_strings entered\nstrings: '%s'\n", strings);
	if ((isalnum(*strings) != 0) && 
		(isalnum(*(strings + strlen(strings) - 1)) != 0)) {
		replace_string(mes, "$replace$", strings);
	}
	else {
		sep = *strings;
		dbg("sep: '%c'\n", sep);
		end = strings + strlen(strings);
		pos = strings + 1;
		while (pos < end) {
			atr = pos;
			pos = strchr(atr, sep);
			if (pos != NULL) {
				*pos = '\0';
				val = pos + 1;
				pos = strchr(val, sep);
				if (pos != NULL) {
					*pos = '\0';
					pos++;
				}
			}
			dbg("atr: '%s'\nval: '%s'\n", atr, val);
			if ((atr != NULL) && (val != NULL)) {
				repl = str_alloc(strlen(val) + 3);
				if (repl == NULL) {
					printf("failed to allocate memory\n");
					exit_code(2, __PRETTY_FUNCTION__, "memory allocation failure");
				}
				sprintf(repl, "$%s$", atr);
				replace_string(mes, repl, val);
				free(repl);
			}
			dbg("pos: '%s'\n", pos);
		}
	}
	dbg("mes:\n'%s'\n", mes);
}

/* insert \r in front of all \n if it is not present already
 * and and a trailing \r\n is not present */
void insert_cr(char *mes) {
	char *lf, *pos, *backup;

	pos = mes;
	lf = strchr(pos, '\n');
	while ((lf != NULL) && (lf >= mes+1) && (*(--lf) != '\r')) {
		backup=str_alloc(strlen(lf)+2);
		strcpy(backup, lf+1);
		*(lf+1) = '\r';
		strcpy(lf+2, backup);
		free(backup);
		pos = lf+3;
		lf = strchr(pos, '\n');
	}
	lf = STRCASESTR(mes, "\r\n\r\n");
	if (lf == NULL) {
		lf = mes + strlen(mes);
		sprintf(lf, "\r\n");
	}
}

/* sipmly swappes the content of the two buffers */
void swap_buffers(char *fst, char *snd) {
	char *tmp;

	if (fst == snd)
		return;
	tmp = str_alloc(strlen(fst)+1);
	strcpy(tmp, fst);
	strcpy(fst, snd);
	strcpy(snd, tmp);
	free(tmp);
}

void swap_ptr(char **fst, char **snd) {
	char *tmp;

	tmp = *fst;
	*fst = *snd;
	*snd = tmp;
}

/* trashes one character in buff randomly */
void trash_random(char *message) {
	int r;
	float t;
	char *position;

	t=(float)rand()/RAND_MAX;
	r=(int)(t * (float)strlen(message));
	position=message+r;
	r=(int)(t*(float)255);
	*position=(char)r;
	if (verbose > 2)
		printf("request:\n%s\n", message);
}

/* this function is taken from traceroute-1.4_p12 
   which is distributed under the GPL and it returns
   the difference between to timeval structs */
double deltaT(struct timeval *t1p, struct timeval *t2p) {
	register double dt;

	dt = (double)(t2p->tv_sec - t1p->tv_sec) * 1000.0 +
			(double)(t2p->tv_usec - t1p->tv_usec) / 1000.0;
	return (dt);
}

/* returns one if the string contains only numbers otherwise zero */
int is_number(char *number) {
	int digit = 1;
	if (strlen(number) == 0) {
		return 0;
	}
	while (digit && (*number != '\0')) {
		digit = isdigit(*number);
		number++;
	}
	return digit ? 1 : 0;
}

/* tries to convert the given string into an integer. it strips
 * white-spaces and exits if an error happens */
int str_to_int(int mode, char *num) {
	int ret, len;
	char *end, *start;
	char *backup = NULL;

	len = strlen(num);
	if (len == 0) {
		fprintf(stderr, "error: string has zero length: '%s'\n", num);
		ret = 2;
		goto error;
	}
	/* we need to make a backup to insert the zero char */
	backup = malloc(len + 1);
	if (!backup) {
		fprintf(stderr, "error: failed to allocate memory\n");
		ret = 2;
		goto error;
	}
	memcpy(backup, num, len + 1);

	start = backup;
	end = backup + len;
	while (isspace(*start) && (start < end)) {
		start++;
	}
	if (start == end) {
		fprintf(stderr, "error: string is too short: '%s'\n", num);
		ret = 2;
		goto error;
	}
	if (mode == 0) {
		end--;
		while (isspace(*end) && (end > start)) {
			end--;
		}
		if (end != (backup + len - 1)) {
			end++;
			*end = '\0';
		}
	}
	else {
		end = start;
		end++;
		while ((end < backup + len) && *end != '\0' && !isspace(*end)) {
			end++;
		}
		*end = '\0';
	}
	if (!is_number(start)) {
		fprintf(stderr, "error: string is not a number: '%s'\n", start);
		ret = 2;
		goto error;
	}
	ret = atoi(start);
	if (ret >= 0) {
		free(backup);
		return ret;
	}
	else {
		fprintf(stderr, "error: failed to convert string to integer: '%s'\n", num);
		ret = 2;
	}
error:
	if (backup) {
		free(backup);
	}
	if (mode == 0) {
		/* libcheck expects a return value not an exit code */
#ifndef RUNNING_CHECK
		exit_code(ret, __PRETTY_FUNCTION__, NULL);
#endif
	}
	return (ret * - 1);
}

/* reads into the given buffer from standard input until the EOF
 * character, LF character or the given size of the buffer is exceeded */
int read_stdin(char *buf, int size, int ret) {
	int i, j;

	for(i = 0; i < size - 1; i++) {
		j = getchar();
		if (((ret == 0) && (j == EOF)) ||
			((ret == 1) && (j == '\n'))) {
			*(buf + i) = '\0';
			return i;
		}
		else {
			*(buf + i) = j;
		}
	}
	*(buf + i) = '\0';
	if (verbose)
		fprintf(stderr, "warning: readin buffer size exceeded\n");
	return i;
}

int safe_strcpy(char *dst, size_t *dst_len, char const *src) {
	size_t amt = *dst_len;

	size_t i;

	for (i = 0; i < amt && src[i]; ++i) {
		dst[i] = src[i];
	}

	*dst_len = i + 1;

	dst[i - 1] = '\0';

	return i < amt;
}

char *cpy_str_alloc(char const *str) {
	size_t len;
	char *new_str;
	len = strlen(str);
	new_str = safe_malloc(len + 1);
	strcpy(new_str, str);
	return new_str;
}

void construct_sipsak_address(struct sipsak_address *address, char const *address_str, int port) {
	if (port == 0) {
		address->port = 5060;
	} else if (port < 0 || port > 65535) {
		fprintf(stderr, "port %d is out of range.", port);
		exit_code(2, __PRETTY_FUNCTION__, "port is out of range");
	} else {
		address->port = port;
	}
	address->address = cpy_str_alloc(address_str);
}

void destroy_sipsak_address(struct sipsak_address *address) {
	free(address->address);
	address->address = NULL;
	address->port = 0;
}

void destroy_sipsak_addresses(struct sipsak_address *addresses, size_t num_addresses) {
	size_t i;
	for (i = 0; i < num_addresses; ++i) {
		destroy_sipsak_address(&addresses[i]);
	}
	free(addresses);
}

static size_t create_address_no_lookup(struct sipsak_address **address, char const *host, unsigned int port) {
	*address = safe_malloc(sizeof(struct sipsak_address));
	construct_sipsak_address(*address, host, port);
	return 1;
}

size_t get_addresses(struct sipsak_address **addresses, char const *host, unsigned int port, int *transport) {
	size_t num_addresses = 0;
	if (!is_ip(host) && !port) {
		/*num_addresses = getsrvaddress(addresses, host, transport);*/
	}
	if (num_addresses == 0) {
		num_addresses = create_address_no_lookup(addresses, host, port);
	}
	return num_addresses;
}

char const *sipsak_address_stringify(struct sipsak_address const *address) {
	return address ? address->address : "";
}

unsigned int read_big_endian_16(unsigned char const *buf) {
	unsigned int value = 0;
    value = ((unsigned int)buf[0] << 8);
    value |= ((unsigned int)buf[1]);
    return value;
}

void *safe_malloc(size_t size) {
	void *ptr;
	ptr = malloc(size);
	if (ptr == NULL) {
		fprintf(stderr, "error: memory allocation for %lu bytes failed\n", size);
		exit_code(255, __PRETTY_FUNCTION__, "memory allocation failure");
	}
	return ptr;
}

/* tries to allocate the given size of memory and sets it all to zero.
 * if the allocation fails it exits */
void *str_alloc(size_t size) {
	char *ptr;
#ifdef HAVE_CALLOC
	ptr = calloc(1, size);
#else
	ptr = malloc(size);
#endif
	if (ptr == NULL) {
		fprintf(stderr, "error: memory allocation for %lu bytes failed\n", size);
		exit_code(255, __PRETTY_FUNCTION__, "memory allocation failure");
	}
#ifndef HAVE_CALLOC
	memset(ptr, 0, size);
#endif
	return ptr;
}

void dbg(char* format, ...) {
#ifdef DEBUG
	va_list ap;

	fprintf(stderr, "DEBUG: ");
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fflush(stderr);
	va_end(ap);
#endif
}
