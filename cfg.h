#ifndef __CFG_H
#define __CFG_H

#include <ctype.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <sys/types.h>

#ifdef DMALLOC
#include <dmalloc.h>
#endif

#include "config.h"


/* === TYPEDEFS ============================================================ */
typedef struct _char_vector char_vector;
struct _char_vector {
    /* size of the vector */
    int size;
    /* number of the elements memory allocated for */
    int max;
    /* array of the elements */ 
    char **val;
};

typedef struct _nameval nameval;
struct _nameval {
    /* name */
    char *name;
    /* value */
    char *val;
};

typedef struct _nameval_vector nameval_vector;
struct _nameval_vector {
    /* size of the vector */
    int size;
    /* number of the elements memory allocated for */
    int max;
    /* array of the elements */ 
    nameval **val;
};


typedef struct _queue MESSAGE;
struct _queue
{
    char *seqnum;		/* sequence number, as it came from cgpro */
    char *filename;		/* filename to check */
    char *sender;		/* e-mail of the message sender */
    char_vector *recipients;	/* e-mails of the message recipients */
    char *recipient_names;	/* recipients in one string */
    char_vector *domains;	/* domains of the sender and recipients */ 
    unsigned long smtp;		/* SMTP server of the sender */
    int is_sender_local;	/* set if the sender is local */
    char_vector *viruses;	/* contains names of viruses */
    char *virus_names;		/* virus names in one string */
    char *av_message;		/* AV message for Undeliverable */
    int is_spam;		/* if the message was detected as spam */
    float spam_score;		/* counted spam score */
    float spam_threshold;	/* spam threshold, if over it's spam */
    char *spam_message;		/* string, containing description of tests */
    int user_spam_action;	/* user's action got from the database */
    char *user;			/* user got from the database */
    int fd;			/* file descriptor for the socket connection */		
    pid_t pid;			/* pid of the process servicing request */
    int deleted;		/* is this entry has been already deleted? */
    MESSAGE *next;		/* pointer to the next member */
};

typedef struct _ip_range ip_range;
struct _ip_range {
    /* from ip address */
    unsigned long from;
    /* to ip address */
    unsigned long to;
};

typedef struct _ip_vector ip_vector;
struct _ip_vector {
    /* size of the vector */
    int size;
    /* number of the elements memory allocated for */
    int max;
    /* array of the elements */ 
    ip_range **val;
};

#include "util.h"

#define CGPAV_CONF      "cgpav.conf"	/* name of the conf file */

/*=============  DEFAULT VALUES FOR CONFIG ===============================*/
/* temporary dir to place attachments for scanning */
#define TMP_DIR "/tmp"

/* notifications From address */
#define ANTIVIRUS_EMAIL "antivirus"

/* what to do when message is infected */
/* actions are: none, reject, discard, addheader */
/* default is "reject" */ 
#define INFECTED_ACTION "discard" 

/* mail header to add when a virus was found */
#define INFECTED_HEADER "X-Virus-Flag: Yes"

/* add the mail header when no virus was found */
#define ADD_NOT_INFECTED_HEADER 0
/* mail header to add when no virus was found */
#define NOT_INFECTED_HEADER "X-Virus-Scanned: by cgpav"

/* set to 1 to send notification to the virus sender, else set to 0 */
#define SENDER_NOTIFICATION 1
/* set to 1 to send notifications to the recipients, else set to 0 */
#define RECIPIENTS_NOTIFICATION 1

/* enable sending virus notifications to the postmaster of the mail server */
#define POSTMASTER_NOTIFICATION 0
/* postmaster's account */
#define POSTMASTER_ACCOUNT "postmaster"
/* enable sending notifications to postmasters of the virtual domains */
/* 0 - no notifications, 1 - all notifications: to and from */
/* 2 - only viruses from his users, 3 - only viruses to his users */
#define VIRTUAL_POSTMASTER_NOTIFICATION 0
/* domains to send notifications for */
#define VIRTUAL_DOMAINS ""
/* first part of the virtual domains postmasters' accounts */
#define VIRTUAL_POSTMASTER_ACCOUNT "postmaster"
/* enable sending notifications to local users identified by their IP */
/* 0 - no notifications to local users */
/* 1 - all notifications: to the local user and his recipients */
/* 2 - only to the local user, 3 - only to recipients */
#define LOCAL_NOTIFICATION 0
/* local networks for the above */
#define LOCAL_NETWORKS ""
/* local domains for notifications */
#define LOCAL_DOMAINS ""
/* notifications depending on the fake virus names */
#define VIRUS_NAME_NOTIFICATION 0
/* fake virus names containing these strings */
#define FAKE_VIRUS_STRINGS ""
/* add the original message headers into the notification */
#define ORIGINAL_MESSAGE_HEADERS 0

/* max num of errors while we reject messages, then we just say OK */
#define MAX_ERRORS 20
/* max len of input string */
#define MAX_INPUT_LEN 4096

/* max num of childs we may have each moment */
#define MAX_CHILDS 5
/* and min value */
#define MAX_CHILDS_MIN 2
/* max value of the above field */
#define MAX_CHILDS_MAX 25
/* max num of errors while we reject messages, then we just say OK */
#define MAX_ERRORS 20
/* min value of the above field */
#define MAX_ERRORS_MIN 5
/* max value of the above field */
#define MAX_ERRORS_MAX 200

/* avp daemon control socket */
#define AVPCTL_FILENAME "/var/run/AvpCtl"
/* sophos daemon (sophie) socket */
#define SOPHOS_SOCKET "/var/run/sophie"
/* clamav clamd socket */
#define CLAMD_SOCKET "/tmp/clamd"
/* trend micro trophie socket */
#define TROPHIE_SOCKET "/var/run/trophie"
/* drweb unix socket */
#define DRWEBD_SOCKET "/var/run/drwebd.socket"

/* some infected file extensions */
#define INFECTED_EXTENSIONS ""

/* quarantine infected messages */
#define VIRUS_QUARANTINE 0
/* dir to quarantine infected messages to */
#define VIRUS_QUARANTINE_DIR ""
/* create collection of the original viruses */
#define VIRUS_COLLECTION 0
/* where to store collection */
#define VIRUS_COLLECTION_DIR ""

/* anti-virus daemon timeout */
#define AV_TIMEOUT 300
/* min value of the above */
#define AV_TIMEOUT_MIN 60

/* log daemon facility */
#define LOG_FACILITY LOG_LOCAL0

/* charset and languages for additional notifications, set to 1 to include */
#define CHARSET "us-ascii"
#define SENDER_SUBJECT "VIRUS in your message"
#define RECIPIENT_SUBJECT "VIRUS in message to you"
#define OWN_TEXT ""
#define RUSSIAN 0
#define GERMAN 0
#define FRENCH 0
#define SPANISH 0
#define ITALIAN 0
#define TATAR 0
#define LATVIAN 0
#define UKRAINIAN 0
#define DUTCH 0

/* ===================== SPAMASSASSIN =============================== */
/* enable spamassassin scanning */
#define ENABLE_SPAMASSASSIN 0
/* scan or not messages from local senders */
#define SPAM_SCAN_LOCAL 0
/* type of the socket: 0 - unix, 1 - tcp */
#define SPAMASSASSIN_SOCKET_TYPE 0 
/* spamassassin daemon (spamd) socket */
#define SPAMASSASSIN_SOCKET "/var/run/spam"
/* spamd host */
#define SPAMASSASSIN_HOST "127.0.0.1"
/* spamd listening port */
#define SPAMASSASSIN_PORT 783
/* what to do when spam is detected */
/* actions are: none - 0, reject - 2, discard - 3, addheader - 4, */
/* addheaderall - 6 */
/* default is "reject" */
#define SPAM_ACTION "reject"
/* to print extra_spam_action when is reached */
#define EXTRA_SPAM_SCORE 15
/* action when extra_spam_score is reached */
/* default is reject */
#define EXTRA_SPAM_ACTION "reject"
/* spam mail header, added when addheader action defined */
#define SPAM_HEADER ""
/* spam level header, */
/* the number of * (or spam_level_char) in it defines the spam hits */
#define SPAM_LEVEL_HEADER 0
/* spam level header char, default '*' */
#define SPAM_LEVEL_CHAR '*'
/* maximum number of bytes in a message to be scanned for spam */
#define MAX_SPAMSCAN_SIZE 51200
/* the minimum value of the above */
#define MAX_SPAMSCAN_SIZE_MIN 5120
/* text of the message to the spam sender */
#define ANTISPAM_MESSAGE "This user rejects any e-mails from you!\nYou seems to be a spammer."
/* aliases of the mail server Example: mail */
#define DOMAIN_ALIASES ""
/* enable spam quarantine */
#define SPAM_QUARANTINE 0
/* dir where copy spam messages to */
#define SPAM_QUARANTINE_DIR ""


/* ================= DATABASE ================================ */
/* database host name */
#define DB_HOST "localhost"
/* database port number */
#define DB_PORT 0
/* database's user name */
#define DB_USERNAME ""
/* user password */
#define DB_PASSWORD ""
/* database name */
#define DB_DATABASE ""

/* ================== RESTRICTIONS ============================ */
/* restrictions in scanning certain domains */
/* 0 - disable, 1 - enable and use scan_domains */
/* 2 - enable and use not_scan_domains */
#define RESTRICTIONS 0
/* define domains to scan */
#define SCAN_DOMAINS ""
/* define domains not to scan */
#define NOT_SCAN_DOMAINS ""


struct settings {
    char *antivirus_email;
    int infected_action;	
    char *infected_header;
    int add_not_infected_header;
    char *not_infected_header;
    int sender_notification;
    int recipients_notification;
    int postmaster_notification;
    char *postmaster_account;
    int virtual_postmaster_notification;
    char_vector *virtual_domains;
    char *virtual_postmaster_account;
    int local_notification;
    ip_vector *local_networks;
    char_vector *local_domains;
    int virus_name_notification;
    char_vector *fake_virus_strings;
    int original_message_headers;
    char *cgpro_home;
    char *cgpro_submitted;
    char *tmp_dir;
    unsigned int cgpro_timeout;
    int max_childs;
    int max_errors;
    char *avpctl_filename;
    char *sophos_socket;
    char *clamd_socket;
    char *trophie_socket;
    char *drwebd_socket;
    char_vector *infected_extensions;
    int virus_quarantine;
    char *virus_quarantine_dir;
    int virus_collection;
    char *virus_collection_dir;
    int av_timeout;
    int log_facility;
    char *viruses_dir;    
    char *charset;
    char *sender_subject;
    char *recipient_subject;
    char *own_text;
    int russian;    
    int german;
    int french;
    int spanish;
    int italian; 
    int tatar;
    int latvian;
    int ukrainian;                                   
    int dutch;
    int enable_spamassassin;
    int spam_scan_local;
    int spamassassin_socket_type;
    char *spamassassin_socket;
    char *spamassassin_host;
    int spamassassin_port;
    int spam_action;
    float extra_spam_score;
    int extra_spam_action;
    char *spam_header;
    int spam_level_header;
    char spam_level_char;
    unsigned long max_spamscan_size; 
    char *antispam_message;
    nameval_vector *domain_aliases;
    int spam_quarantine;
    char *spam_quarantine_dir;
    char *db_host;
    int db_port;
    char *db_username;
    char *db_password;
    char *db_database;
    int restrictions;
    char_vector *scan_domains; 
    char_vector *not_scan_domains;
};

/* set variables from the config file */
/* first try to load the user-defined conf file */
/* then look into default dirs */
/* if there is no config file, use defaults from cfg.h */
int set_config(struct settings *sett, char *conf_file_user);

/* free strings in settings structure */
int free_config(struct settings *sett);

#endif
