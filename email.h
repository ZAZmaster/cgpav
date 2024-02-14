#ifndef __EMAIL_H
#define __EMAIL_H

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>

#include "cfg.h"
#include "util.h"

extern struct settings *sett;


/* get e-mail address from the line */
char *parse_email(char *header_string);
/* extract domain from e-mail */
char *extract_domain(char *email);
/* get SMTP address from the header line */
unsigned long parse_smtp(char *header_line);
/* parse message headers to get sender's and recipients' e-mails */
int parse_headers(MESSAGE *mess);


#ifdef DEBUG
/* print what we were able to extract from the headers */
void print_headers(MESSAGE *ptr);
#endif

/* free memory allocated in the parse_header function */
void free_headers(MESSAGE *mess);

/* log viruses and get virus senders and recipients */
int email_notifications(MESSAGE *mess);

/* construct postmaster's email and send e-mail him */
int create_message_postmaster(MESSAGE *mess, char *domain, char *to_from, 
			      int random_val);

/* send notifications for postmasters of the virtual domains */
int send_virtual_postmasters(MESSAGE *mess);

/* send email to virus sender */
int sender_notification(MESSAGE *mess);

/* send e-mail to recipient */
int recipient_notification(MESSAGE *mess, char *recipient, int random_val);

/* send a notification to postmaster */
int postmaster_notification(MESSAGE *mess, char *postmaster_email, 
			    char *to_from, int random_val);


#endif
