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

#ifndef SIPSAK_TRANSPORT_H
#define SIPSAK_TRANSPORT_H

#include "sipsak.h"
#include "shoot.h"
#include "error.h"

#include <time.h>
#ifdef HAVE_SYS_TIME_H
# include <sys/time.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif

#define NO_IP_PREF 0
#define PREF_IPV4  1
#define PREF_IPV6  2

struct sipsak_sr_time {
	struct timeval sendtime;
	struct timeval recvtime;
	struct timeval firstsendt;
	struct timeval starttime;
	struct timeval delaytime;
	int timer_t1;
	int timer_t2;
	int timer_final;
	int timing;
};

/*struct sipsak_con_data {
	struct sockaddr_in adr;
	unsigned int transport;
	unsigned long address;
	int csock;
	int usock;
	int dontsend;
	int dontrecv;
	int connected;
	int symmetric;
	int lport;
	int rport;
	char *buf_tmp;
	int buf_tmp_size;
};*/

enum sipsak_con_error_type {
	ADDRINFO,
	REBIND_CONN,
};

union sipsak_con_error_sys {
	int error_errno;
	int error_gai;
};

struct sipsak_con_error {
	enum sipsak_con_error_type type;
	union sipsak_con_error_sys sys_code;
};

struct sipsak_con_data {
	union sipsak_sockaddr from_adr;
	union sipsak_sockaddr to_adr;
	int transport;
	//union sipsak_sockaddr address;
	/*unsigned long address;*/
	struct sipsak_address *addresses;
	size_t num_addresses, cur_address;
	int csock;
	int usock;
	int dontsend;
	int dontrecv;
	int connected;
	int symmetric;
	in_port_t lport;
	in_port_t rport;
	char *buf_tmp;
	int buf_tmp_size;
};

struct sipsak_counter {
	int send_counter;
	int retrans_r_c;
	int retrans_s_c;
	int randretrys;
	int run;
	int namebeg;
	int nameend;
};

struct sipsak_delay {
	int retryAfter;
	double big_delay;
	double small_delay;
	double all_delay;
};

extern char *transport_str;

void set_addresses(struct sipsak_con_data *cd, struct sipsak_address *addresses, size_t num_addresses);

struct sipsak_address const *get_cur_address(struct sipsak_con_data *cd);

sipsak_err init_network(struct sipsak_con_data *cd, char const *local_ip, char const *ca_file);

void shutdown_network();

void send_message(char* mes, struct sipsak_con_data *cd,
			struct sipsak_counter *sc, struct sipsak_sr_time *srt);

int recv_message(char *buf, int size, int inv_trans,
			struct sipsak_delay *sd, struct sipsak_sr_time *srt,
			struct sipsak_counter *count, struct sipsak_con_data *cd,
			struct sipsak_regexp *reg, enum sipsak_modes mode, int cseq_counter,
      char *request, char *response);

sipsak_err set_target(struct sipsak_con_data *con, char const *domainname, int ignore_ca_fail);
#endif
