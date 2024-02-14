#ifndef __COMMONCOMM_H
#define __COMMONCOMM_H

#include <ctype.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>
#include <netinet/in.h>
#include <netdb.h>

#include "cfg.h"

#include "email.h"
#include "util.h"


/* choose what Anti-Virus daemon to use */
#ifdef AVP
#include "avpcomm.h"
#endif
#ifdef KAV
#include "kavcomm.h"
#endif
#ifdef SOPHOS
#include "sophoscomm.h"
#endif
#ifdef CLAMAV
#include "clamdcomm.h"
#endif
#ifdef TROPHIE
#include "trophiecomm.h"
#endif
#ifdef DRWEB
#include "drwebcomm.h"
#endif

#ifdef UNMIME_LIB
#include "uudeview.h"
#endif


#ifdef SPAMD
#include "spamdcomm.h"

#ifdef MYSQL_DB
#include "mysqlcomm.h"
#endif

#ifdef PGSQL_DB
#include "pgsqlcomm.h"
#endif

#endif /* SPAMD */


extern struct settings *sett;

/* connect to the control socket and return its filedescriptor */	
int connect_socket(char *path);

/* connect to the TCP socket and return its filedescriptor */	
int connect_tcp(char *host, int port);

/* close connection to av */
void av_disconnect(int fd);

/* main virus scanning procedure */
int av_scan_file(MESSAGE *mess);

/* destructor */
void free_av_scan_file(MESSAGE *mess);

/* check if the file extension is suspicious */
int check_extension(MESSAGE *mess, char *filename);

/* create detailed message with the virus filenames */
int create_av_message(MESSAGE *mess, char *filename, 
		      char *virusname, char *description);
			
/* print out report in the cgpro string format */
void av_say_message(MESSAGE *mess);

/* copy infected messages to the virus quarantine and collection */
int copy_infected(MESSAGE *mess, char *filename, char *virus_name);

/* copy spam into quarantine dir */
int copy_spam(MESSAGE *mess);

/* scan the message for spam */
int spam_scan_file(MESSAGE *mess);

/* destructor */
void free_spam_scan_file(MESSAGE *mess);


#endif
