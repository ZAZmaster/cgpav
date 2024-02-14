/* $Id: cfg.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "cfg.h"

#define LINE_LEN_MAX    1024			/* actual max line length  */
#define BUFFERSIZE      LINE_LEN_MAX + 2	/* ... including \n and \0 */
#define SPLIT_PATTERN	",;\t "			/* used in splitting strings */


static int false_true(char *val)
{

    if ((strcasecmp(val, "true") == 0)
	|| (strcasecmp(val, "on") == 0)
	|| (strcmp(val, "1") == 0)
	|| (strcasecmp(val, "yes") == 0)
	)
	return 1;
    else
	return 0;
}

static int notification_action(char *val)
{

    if ((strcasecmp(val, "false") == 0) || (strcasecmp(val, "no") == 0))
	return 0; 
    else if ((strcasecmp(val, "true") == 0) || (strcasecmp(val, "all") == 0))
	return 1; 
    else if (strcasecmp(val, "from") == 0)
	return 2; 
    else if (strcasecmp(val, "to") == 0)
	return 3; 
    else
	return 0;
}


static int convert_action(char *val)
{

    if ((strcasecmp(val, "none") == 0) || (strcasecmp(val, "no") == 0))
	return 0; 
    else if (strcasecmp(val, "reject") == 0)
	return 2; 
    else if (strcasecmp(val, "discard") == 0)
	return 3; 
    else if (strcasecmp(val, "addheader") == 0)
	return 4; 
    else if (strcasecmp(val, "addheaderall") == 0)
	return 6; 
    else if (strcasecmp(val, "addheaderjunk") == 0)
	return 7; 
    else if (strcasecmp(val, "addheaderjunk") == 0)
	return 8; 
    else
	return 0;
}

/* convert the string with kilo and megabytes into bytes */
static unsigned long convert_to_bytes(char *str)
{
    unsigned long val = 0;
    char *tmp = NULL;

    if (!str)
	return 0;
    
    /* remove spaces */
    clear_string(" ", &str);
    /* the value must be only positive */
    clear_string("-", &str);

    /* kilobytes */    
    if (strchr(str, 'K') || strchr(str, 'k')) {
	val = strtoul(str, &tmp, 10);
	if (val)
	    val *= 1024;	
    }
    /* megabytes */
    else if (strchr(str, 'M') || strchr(str, 'm')) {
	val = strtoul(str, &tmp, 10);
	if (val)
	    val *= 1024 * 1024;
    }
    else {
	val = strtoul(str, &tmp, 10);    
    }

    return val;
}

/* set default values to config */
static int load_defaults(struct settings *sett)
{
    sett->cgpro_home = strdup(CGPRO_HOME);
    if (!sett->cgpro_home)
	return -1;
    sett->cgpro_submitted = strdup(CGPRO_SUBMITTED);
    if (!sett->cgpro_submitted)
	return -1;
    sett->tmp_dir = strdup(TMP_DIR);
    if (!sett->tmp_dir)
	return -1;

    sett->antivirus_email = strdup(ANTIVIRUS_EMAIL);
    if (!sett->antivirus_email)
	return -1;
    sett->infected_action = convert_action(INFECTED_ACTION);
    sett->infected_header = strdup(INFECTED_HEADER);
    if (!sett->infected_header)
	return -1;
    sett->add_not_infected_header = ADD_NOT_INFECTED_HEADER;
    sett->not_infected_header = strdup(NOT_INFECTED_HEADER);
    if (!sett->not_infected_header)
	return -1;	
    sett->sender_notification = SENDER_NOTIFICATION;
    sett->recipients_notification = RECIPIENTS_NOTIFICATION;
    sett->postmaster_notification = POSTMASTER_NOTIFICATION;
    sett->postmaster_account = strdup(POSTMASTER_ACCOUNT);
    if (!sett->postmaster_account)
	return -1;
    sett->virtual_postmaster_notification = VIRTUAL_POSTMASTER_NOTIFICATION;	
    /* there can be many virtual domains */
    sett->virtual_domains = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->virtual_domains)
        return -1;
    /* initialise  */
    sett->virtual_domains->size = 0;
    /* add default elements */
    if (split_string(SPLIT_PATTERN, VIRTUAL_DOMAINS, 
		 sett->virtual_domains))
	return -1;	 
    sett->virtual_postmaster_account = strdup(VIRTUAL_POSTMASTER_ACCOUNT);
    if (!sett->virtual_postmaster_account)
	return -1;

    sett->local_notification = LOCAL_NOTIFICATION;	
    /* there can be many local networks */
    sett->local_networks = (ip_vector *)malloc(sizeof(ip_vector));
    if (!sett->local_networks)
        return -1;
    /* initialise the number of elements in the vector */
    sett->local_networks->size = 0;
    /* add default elements */
    if (split_ip_string(SPLIT_PATTERN, LOCAL_NETWORKS, 
		 sett->local_networks))
	return -1;	 

    sett->local_domains = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->local_domains)
        return -1;
    sett->local_domains->size = 0;
    /* add default elements */
    if (split_string(SPLIT_PATTERN, LOCAL_DOMAINS, sett->local_domains))
	return -1;	 
	
    sett->virus_name_notification = VIRUS_NAME_NOTIFICATION;	
    sett->fake_virus_strings = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->fake_virus_strings)
        return -1;
    sett->fake_virus_strings->size = 0;
    /* add default elements */
    if (split_string(SPLIT_PATTERN, FAKE_VIRUS_STRINGS, 
		 sett->fake_virus_strings))
	return -1;	 
    sett->original_message_headers = ORIGINAL_MESSAGE_HEADERS;
    	
    sett->max_childs = MAX_CHILDS;
    sett->max_errors = MAX_ERRORS;
    sett->avpctl_filename = strdup(AVPCTL_FILENAME);
    if (!sett->avpctl_filename)
	return -1;
    sett->sophos_socket = strdup(SOPHOS_SOCKET);
    if (!sett->sophos_socket)
	return -1;
    sett->clamd_socket = strdup(CLAMD_SOCKET);
    if (!sett->clamd_socket)
	return -1;
    sett->trophie_socket = strdup(TROPHIE_SOCKET);
    if (!sett->trophie_socket)
	return -1;
    sett->drwebd_socket = strdup(DRWEBD_SOCKET);
    if (!sett->drwebd_socket)
	return -1;

    /* there can be many infected extensions, so we use a vector */
    sett->infected_extensions = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->infected_extensions)
        return -1;
    /* initialise the number of elements in the vector */
    sett->infected_extensions->size = 0;
    /* add default elements */
    if (split_string(SPLIT_PATTERN, INFECTED_EXTENSIONS, 
		 sett->infected_extensions))
	return -1;	 
    
    sett->virus_quarantine = VIRUS_QUARANTINE;
    sett->virus_quarantine_dir = strdup(VIRUS_QUARANTINE_DIR);
    if (!sett->virus_quarantine_dir)
	return -1;
    sett->virus_collection = VIRUS_COLLECTION;
    sett->virus_collection_dir = strdup(VIRUS_COLLECTION_DIR);
    if (!sett->virus_collection_dir)
	return -1;
		
    sett->av_timeout = AV_TIMEOUT;

    sett->log_facility = LOG_FACILITY;
    sett->charset = strdup(CHARSET);
    if (!sett->charset)
	return -1;
    sett->sender_subject = strdup(SENDER_SUBJECT);
    if (!sett->sender_subject)
	return -1;
    sett->recipient_subject = strdup(RECIPIENT_SUBJECT);
    if (!sett->recipient_subject)
	return -1;
    sett->own_text = strdup(OWN_TEXT);
    if (!sett->own_text)
	return -1;

    sett->russian = RUSSIAN;
    sett->german = GERMAN;
    sett->french = FRENCH;
    sett->spanish = SPANISH;
    sett->italian = ITALIAN;
    sett->tatar = TATAR;
    sett->latvian = LATVIAN;
    sett->ukrainian = UKRAINIAN;
    sett->dutch = DUTCH;

    sett->enable_spamassassin = ENABLE_SPAMASSASSIN;
    sett->spam_scan_local = SPAM_SCAN_LOCAL;

    sett->spamassassin_socket_type = SPAMASSASSIN_SOCKET_TYPE;
    sett->spamassassin_socket = strdup(SPAMASSASSIN_SOCKET);
    if (!sett->spamassassin_socket)
	return -1;
    sett->spamassassin_host = strdup(SPAMASSASSIN_HOST);
    if (!sett->spamassassin_host)
	return -1;
    sett->spamassassin_port = SPAMASSASSIN_PORT;	
    sett->spam_action = convert_action(SPAM_ACTION);	
    sett->extra_spam_score = EXTRA_SPAM_SCORE;
    sett->extra_spam_action = convert_action(EXTRA_SPAM_ACTION);
    sett->spam_header = strdup(SPAM_HEADER);
    if (!sett->spam_header)
	return -1;    
    sett->spam_level_header = SPAM_LEVEL_HEADER;	
    sett->spam_level_char = SPAM_LEVEL_CHAR;
    sett->max_spamscan_size = MAX_SPAMSCAN_SIZE;
    sett->antispam_message = strdup(ANTISPAM_MESSAGE);
    if (!sett->antispam_message)
	return -1;
    sett->domain_aliases = (nameval_vector *)malloc(sizeof(nameval_vector));
    if (!sett->domain_aliases)
        return -1;
    sett->domain_aliases->size = 0;
    if (split_hash_string(SPLIT_PATTERN, DOMAIN_ALIASES, 
		 sett->domain_aliases))
	return -1;	 
    sett->spam_quarantine = SPAM_QUARANTINE;
    sett->spam_quarantine_dir = strdup(SPAM_QUARANTINE_DIR);
    if (!sett->spam_quarantine_dir)
	return -1;
	

    sett->db_host = strdup(DB_HOST);
    if (!sett->db_host)
	return -1;
    sett->db_port = DB_PORT;
    sett->db_username = strdup(DB_USERNAME);
    if (!sett->db_username)
	return -1;
    sett->db_password = strdup(DB_PASSWORD);
    if (!sett->db_password)
	return -1;
    sett->db_database = strdup(DB_DATABASE);
    if (!sett->db_database)
	return -1;

    sett->restrictions = RESTRICTIONS;	
    sett->scan_domains = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->scan_domains)
        return -1;
    sett->scan_domains->size = 0;
    if (split_string(SPLIT_PATTERN, SCAN_DOMAINS, 
		 sett->scan_domains))
	return -1;	 
    sett->not_scan_domains = (char_vector *)malloc(sizeof(char_vector));
    if (!sett->not_scan_domains)
        return -1;
    sett->not_scan_domains->size = 0;
    if (split_string(SPLIT_PATTERN, NOT_SCAN_DOMAINS, 
		 sett->not_scan_domains))
	return -1;	 


    return 0;
}


/* read and parse the config file */
static int read_config(char *filename, struct settings *sett)
{
    char buffer[BUFFERSIZE];
    char *line;
    char *cfg_name;
    char *cfg_data;
    char *p;
    int i;
    float q;
    FILE *cfg_file;


    cfg_file = fopen(filename, "r");
    if (!cfg_file)
	return -1;


    while (fgets(buffer, BUFFERSIZE, cfg_file)) {
	/* clip off optional comment tail indicated by a # sign */
	if ((line = strchr(buffer, '#')) || (line = strchr(buffer, ';')))
	    *line = '\0';
	else
	    line = buffer + strlen(buffer);

	/* clip off trailing and leading white space */
	line--;
	while ((isspace((int)*line)) && (line >= buffer))
	    *line-- = '\0';
	line = buffer;
	while (isspace((int)*line))
	    line++;
	if (strlen(line) == 0)
	    continue;

	cfg_name = strtok(line, "=");
	if (cfg_name) {
	    p = cfg_name;
	    for (; *p != '\0'; p++) {
		if (isspace((int)*p)) {
		    *p = '\0';
		    break;
		}
	    }
	    cfg_data = strtok(NULL, "");
	    if (cfg_data) {
		while (isspace((int)*cfg_data))
		    cfg_data++;
		if (*cfg_data == '=')
		    cfg_data++;
		while (isspace((int)*cfg_data))
		    cfg_data++;
		/* get rid of the last "/" sign */
		p = cfg_data + strlen(cfg_data) - 1;
		if (*p == '/')
		    *p = '\0';
		if (*cfg_data == '-')
		    cfg_data++;

		/* tab and new line characters */
		for (p = cfg_data; *p != '\0'; p++) {
		    if ((*p == '\\')
			&& ((*(p + 1) == 'n') || (*(p + 1) == 't'))) {
			*p = ' ';
			p++;
			if (*p == 'n')
			    *p = '\n';
			else
			    *p = '\t';
		    }
		}
	    }


	    /* ======================================================== */
	    if ((strcasecmp(cfg_name, "antivirus_email") == 0)
		&& cfg_data && (strcmp(cfg_data, ANTIVIRUS_EMAIL) != 0)) {
		sett->antivirus_email = (char *)realloc(sett->antivirus_email,
							strlen(cfg_data) + 1);
		if (!sett->antivirus_email)
		    return -1;
		strcpy(sett->antivirus_email, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "infected_action") == 0)
		     && cfg_data) {
		sett->infected_action = convert_action(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "infected_header") == 0)
		&& cfg_data && (strcmp(cfg_data, INFECTED_HEADER) != 0)) {
		sett->infected_header =
		    (char *)realloc(sett->infected_header,
				    strlen(cfg_data) + 1);
		if (!sett->infected_header)
		    return -1;
		strcpy(sett->infected_header, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "add_not_infected_header") == 0)
		     && cfg_data) {
		sett->add_not_infected_header = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "not_infected_header") == 0)
		&& cfg_data && (strcmp(cfg_data, NOT_INFECTED_HEADER) != 0)) {
		sett->not_infected_header =
		    (char *)realloc(sett->not_infected_header,
				    strlen(cfg_data) + 1);
		if (!sett->not_infected_header)
		    return -1;
		strcpy(sett->not_infected_header, cfg_data);
	    }

	    else if ((strcasecmp(cfg_name, "sender_notification") == 0)
		     && cfg_data) {
		sett->sender_notification = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "recipients_notification") == 0)
		     && cfg_data) {
		sett->recipients_notification = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "postmaster_notification") == 0)
		     && cfg_data) {
		sett->postmaster_notification = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "postmaster_account") == 0)
		&& cfg_data && (strcmp(cfg_data, POSTMASTER_ACCOUNT) != 0)) {
		sett->postmaster_account = (char *)realloc(sett->postmaster_account,
							strlen(cfg_data) + 1);
		if (!sett->postmaster_account)
		    return -1;
		strcpy(sett->postmaster_account, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, 
		      "virtual_postmaster_notification") == 0)
		     && cfg_data) {
		sett->virtual_postmaster_notification 
		    = notification_action(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "virtual_domains") == 0)
		&& cfg_data && (strcmp(cfg_data, VIRTUAL_DOMAINS) != 0)) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
				 sett->virtual_domains))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "virtual_postmaster_account") == 0)
		&& cfg_data 
		&& (strcmp(cfg_data, VIRTUAL_POSTMASTER_ACCOUNT) != 0)) {
		sett->virtual_postmaster_account = 
		    (char *)realloc(sett->virtual_postmaster_account,
				    strlen(cfg_data) + 1);
		if (!sett->virtual_postmaster_account)
		    return -1;
		strcpy(sett->virtual_postmaster_account, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "local_notification") == 0)
		     && cfg_data) {
		sett->local_notification = notification_action(cfg_data);
	    }    
	    else if ((strcasecmp(cfg_name, "local_networks") == 0)
		&& cfg_data && (strcmp(cfg_data, LOCAL_NETWORKS) != 0)) {
		if (split_ip_string(SPLIT_PATTERN, cfg_data, 
				 sett->local_networks))
		    return -1;	     
	    }	    
	    else if ((strcasecmp(cfg_name, "local_domains") == 0)
		&& cfg_data && (strcmp(cfg_data, LOCAL_DOMAINS) != 0)) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
				 sett->local_domains))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "virus_name_notification") == 0)
		     && cfg_data) {
		sett->virus_name_notification = false_true(cfg_data);
	    }    
	    else if ((strcasecmp(cfg_name, "fake_virus_strings") == 0)
		&& cfg_data && (strcmp(cfg_data, FAKE_VIRUS_STRINGS) != 0)) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
				 sett->fake_virus_strings))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "original_message_headers") == 0)
		     && cfg_data) {
		sett->original_message_headers = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "cgpro_home") == 0)
		     && cfg_data && (strcmp(cfg_data, CGPRO_HOME) != 0)) {
		sett->cgpro_home = (char *)realloc(sett->cgpro_home,
						   strlen(cfg_data) + 1);
		if (!sett->cgpro_home)
		    return -1;
		strcpy(sett->cgpro_home, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "cgpro_submitted") == 0)
		     && cfg_data && (strcmp(cfg_data, CGPRO_SUBMITTED) != 0)) {
		sett->cgpro_submitted = (char *)realloc(sett->cgpro_submitted,
							strlen(cfg_data) + 1);
		if (!sett->cgpro_submitted)
		    return -1;
		strcpy(sett->cgpro_submitted, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "tmp_dir") == 0)
		     && cfg_data && (strcmp(cfg_data, TMP_DIR) != 0)) {
		sett->tmp_dir = (char *)realloc(sett->tmp_dir,
							strlen(cfg_data) + 1);
		if (!sett->tmp_dir)
		    return -1;
		strcpy(sett->tmp_dir, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "max_childs") == 0) && cfg_data) {
		i = atoi(cfg_data);
		if (i < MAX_CHILDS_MIN)
		    i = MAX_CHILDS_MIN;
		sett->max_childs = (i > MAX_CHILDS_MAX ? MAX_CHILDS_MAX : i);
	    }
	    else if ((strcasecmp(cfg_name, "max_errors") == 0)) {
		i = atoi(cfg_data);
		if (i < MAX_ERRORS_MIN)
		    i = MAX_ERRORS_MIN;
		sett->max_errors = (i > MAX_ERRORS_MAX ? MAX_ERRORS_MAX : i);
	    }
	    else if ((strcasecmp(cfg_name, "avpctl_filename") == 0)
		     && cfg_data && strcmp(cfg_data, AVPCTL_FILENAME) != 0) {
		sett->avpctl_filename = (char *)realloc(sett->avpctl_filename,
							strlen(cfg_data) + 1);
		if (!sett->avpctl_filename)
		    return -1;
		strcpy(sett->avpctl_filename, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "sophos_socket") == 0)
		     && cfg_data && strcmp(cfg_data, SOPHOS_SOCKET) != 0) {
		sett->sophos_socket = (char *)realloc(sett->sophos_socket,
						      strlen(cfg_data) + 1);
		if (!sett->sophos_socket)
		    return -1;
		strcpy(sett->sophos_socket, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "clamd_socket") == 0)
		     && cfg_data && strcmp(cfg_data, CLAMD_SOCKET) != 0) {
		sett->clamd_socket = (char *)realloc(sett->clamd_socket,
						       strlen(cfg_data) + 1);
		if (!sett->clamd_socket)
		    return -1;
		strcpy(sett->clamd_socket, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "trophie_socket") == 0)
		     && cfg_data && strcmp(cfg_data, TROPHIE_SOCKET) != 0) {
		sett->trophie_socket = (char *)realloc(sett->trophie_socket,
						       strlen(cfg_data) + 1);
		if (!sett->trophie_socket)
		    return -1;
		strcpy(sett->trophie_socket, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "drwebd_socket") == 0)
		     && cfg_data && strcmp(cfg_data, DRWEBD_SOCKET) != 0) {
		sett->drwebd_socket = (char *)realloc(sett->drwebd_socket,
						       strlen(cfg_data) + 1);
		if (!sett->drwebd_socket)
		    return -1;
		strcpy(sett->drwebd_socket, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "infected_extensions") == 0)
		     && cfg_data 
		     && strcmp(cfg_data, INFECTED_EXTENSIONS) != 0) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
			     sett->infected_extensions))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "virus_quarantine") == 0)
		     && cfg_data) {
		sett->virus_quarantine = false_true(cfg_data);
	    }    
	    else if ((strcasecmp(cfg_name, "virus_quarantine_dir") == 0)
		     && cfg_data 
		     && strcmp(cfg_data, VIRUS_QUARANTINE_DIR) != 0) {
		sett->virus_quarantine_dir = 
		    (char *)realloc(sett->virus_quarantine_dir,
				    strlen(cfg_data) + 1);
		if (!sett->virus_quarantine_dir)
		    return -1;
		strcpy(sett->virus_quarantine_dir, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "virus_collection") == 0)
		     && cfg_data) {
		sett->virus_collection = false_true(cfg_data);
	    }    
	    else if ((strcasecmp(cfg_name, "virus_collection_dir") == 0)
		     && cfg_data 
		     && strcmp(cfg_data, VIRUS_COLLECTION_DIR) != 0) {
		sett->virus_collection_dir = 
		    (char *)realloc(sett->virus_collection_dir,
				    strlen(cfg_data) + 1);
		if (!sett->virus_collection_dir)
		    return -1;
		strcpy(sett->virus_collection_dir, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "av_timeout") == 0) && cfg_data) {
		i = atoi(cfg_data);
		sett->av_timeout = (i < AV_TIMEOUT_MIN ? AV_TIMEOUT_MIN : i);
	    }
	    else if ((strcasecmp(cfg_name, "log_facility") == 0) && cfg_data) {
		if ((strcasecmp(cfg_data, "log_daemon") == 0)
		    || (strcasecmp(cfg_data, "daemon") == 0)) {
		    sett->log_facility = LOG_DAEMON;
		}
		else if ((strcasecmp(cfg_data, "log_mail") == 0)
			 || (strcasecmp(cfg_data, "mail") == 0)) {
		    sett->log_facility = LOG_MAIL;
		}
		else if ((strcasecmp(cfg_data, "log_news") == 0)
			 || (strcasecmp(cfg_data, "news") == 0)) {
		    sett->log_facility = LOG_NEWS;
		}
		else if ((strcasecmp(cfg_data, "log_user") == 0)
			 || (strcasecmp(cfg_data, "user") == 0)) {
		    sett->log_facility = LOG_USER;
		}
		else if ((strcasecmp(cfg_data, "log_uucp") == 0)
			 || (strcasecmp(cfg_data, "uucp") == 0)) {
		    sett->log_facility = LOG_UUCP;
		}
		else if ((strcasecmp(cfg_data, "log_local0") == 0)
			 || (strcasecmp(cfg_data, "local0") == 0)) {
		    sett->log_facility = LOG_LOCAL0;
		}
		else if ((strcasecmp(cfg_data, "log_local1") == 0)
			 || (strcasecmp(cfg_data, "local1") == 0)) {
		    sett->log_facility = LOG_LOCAL1;
		}
		else if ((strcasecmp(cfg_data, "log_local2") == 0)
			 || (strcasecmp(cfg_data, "local2") == 0)) {
		    sett->log_facility = LOG_LOCAL2;
		}
		else if ((strcasecmp(cfg_data, "log_local3") == 0)
			 || (strcasecmp(cfg_data, "local3") == 0)) {
		    sett->log_facility = LOG_LOCAL3;
		}
		else if ((strcasecmp(cfg_data, "log_local4") == 0)
			 || (strcasecmp(cfg_data, "local4") == 0)) {
		    sett->log_facility = LOG_LOCAL4;
		}
		else if ((strcasecmp(cfg_data, "log_local5") == 0)
			 || (strcasecmp(cfg_data, "local5") == 0)) {
		    sett->log_facility = LOG_LOCAL5;
		}
		else if ((strcasecmp(cfg_data, "log_local6") == 0)
			 || (strcasecmp(cfg_data, "local6") == 0)) {
		    sett->log_facility = LOG_LOCAL6;
		}
		else if ((strcasecmp(cfg_data, "log_local7") == 0)
			 || (strcasecmp(cfg_data, "local7") == 0)) {
		    sett->log_facility = LOG_LOCAL7;
		}
	    }
	    else if ((strcasecmp(cfg_name, "charset") == 0)
		     && cfg_data && strcmp(cfg_data, CHARSET) != 0) {
		sett->charset = (char *)realloc(sett->charset,
						strlen(cfg_data) + 1);
		if (!sett->charset)
		    return -1;
		strcpy(sett->charset, cfg_data);

	    }
	    else if ((strcasecmp(cfg_name, "sender_subject") == 0)
		     && cfg_data && strcmp(cfg_data, SENDER_SUBJECT) != 0) {
		sett->sender_subject = (char *)realloc(sett->sender_subject,
						       strlen(cfg_data) + 1);
		if (!sett->sender_subject)
		    return -1;
		strcpy(sett->sender_subject, cfg_data);

	    }
	    else if ((strcasecmp(cfg_name, "recipient_subject") == 0)
		     && cfg_data && strcmp(cfg_data, RECIPIENT_SUBJECT) != 0) {
		sett->recipient_subject =
		    (char *)realloc(sett->recipient_subject,
				    strlen(cfg_data) + 1);
		if (!sett->recipient_subject)
		    return -1;
		strcpy(sett->recipient_subject, cfg_data);

	    }
	    else if ((strcasecmp(cfg_name, "own_text") == 0)
		     && cfg_data && strcmp(cfg_data, OWN_TEXT) != 0) {
		sett->own_text = (char *)realloc(sett->own_text,
						 strlen(cfg_data) + 1);
		if (!sett->own_text)
		    return -1;
		strcpy(sett->own_text, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "russian") == 0) && cfg_data) {
		sett->russian = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "german") == 0) && cfg_data) {
		sett->german = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "french") == 0) && cfg_data) {
		sett->french = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spanish") == 0) && cfg_data) {
		sett->spanish = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "italian") == 0) && cfg_data) {
		sett->italian = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "tatar") == 0) && cfg_data) {
		sett->tatar = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "latvian") == 0) && cfg_data) {
		sett->latvian = false_true(cfg_data);
	    }            
	    else if ((strcasecmp(cfg_name, "ukrainian") == 0) && cfg_data) {
		sett->ukrainian = false_true(cfg_data);
	    }            
	    else if ((strcasecmp(cfg_name, "dutch") == 0) && cfg_data) {
		sett->dutch = false_true(cfg_data);
	    }            
	    else if ((strcasecmp(cfg_name, "enable_spamassassin") == 0)
		     && cfg_data) {
		sett->enable_spamassassin = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spam_scan_local") == 0)
		     && cfg_data) {
		sett->spam_scan_local = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spamassassin_socket_type") == 0)
		     && cfg_data) {
		if (strcasecmp(cfg_data, "tcp") == 0)
		    sett->spamassassin_socket_type = 1;
		else
		    sett->spamassassin_socket_type = 0;    
	    }
	    else if ((strcasecmp(cfg_name, "spamassassin_socket") == 0)
		     && cfg_data
		     && strcmp(cfg_data, SPAMASSASSIN_SOCKET) != 0) {
		sett->spamassassin_socket =
		    (char *)realloc(sett->spamassassin_socket,
				    strlen(cfg_data) + 1);
		if (!sett->spamassassin_socket)
		    return -1;
		strcpy(sett->spamassassin_socket, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spamassassin_host") == 0)
		     && cfg_data
		     && strcmp(cfg_data, SPAMASSASSIN_HOST) != 0) {
		sett->spamassassin_host =
		    (char *)realloc(sett->spamassassin_host,
				    strlen(cfg_data) + 1);
		if (!sett->spamassassin_host)
		    return -1;
		strcpy(sett->spamassassin_host, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spamassassin_port") == 0) 
		&& cfg_data) {
		i = atoi(cfg_data);
		if ((i > 1) && (i < 65536))
		    sett->spamassassin_port = i;
	    }
	    else if ((strcasecmp(cfg_name, "spam_action") == 0)
		     && cfg_data) {
		sett->spam_action = convert_action(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "extra_spam_score") == 0)) {
		q = atof(cfg_data);
		if (!q || (q < 5))
		    q = 5;
		sett->extra_spam_score = q;
	    }
	    else if ((strcasecmp(cfg_name, "extra_spam_action") == 0)
		     && cfg_data) {
		sett->extra_spam_action = convert_action(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spam_header") == 0)
		&& cfg_data && (strcmp(cfg_data, SPAM_HEADER) != 0)) {
		sett->spam_header =
		    (char *)realloc(sett->spam_header,
				    strlen(cfg_data) + 1);
		if (!sett->spam_header)
		    return -1;
		strcpy(sett->spam_header, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spam_level_header") == 0)
		     && cfg_data) {
		sett->spam_level_header = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "spam_level_char") == 0)
		     && *cfg_data) {
		sett->spam_level_char = *cfg_data;
	    }
	    else if ((strcasecmp(cfg_name, "max_spamscan_size") == 0)
		     && cfg_data) {
		sett->max_spamscan_size = convert_to_bytes(cfg_data);
		/* fool's protection */
		if (sett->max_spamscan_size < MAX_SPAMSCAN_SIZE_MIN)
		    sett->max_spamscan_size = MAX_SPAMSCAN_SIZE_MIN;
	    }
	    else if ((strcasecmp(cfg_name, "antispam_message") == 0)
		     && cfg_data && strcmp(cfg_data, ANTISPAM_MESSAGE) != 0) {
		sett->antispam_message =
		    (char *)realloc(sett->antispam_message,
				    strlen(cfg_data) + 1);
		if (!sett->antispam_message)
		    return -1;
		strcpy(sett->antispam_message, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "domain_aliases") == 0)
		     && cfg_data 
		     && strcmp(cfg_data, DOMAIN_ALIASES) != 0) {
		if (split_hash_string(SPLIT_PATTERN, cfg_data, 
			     sett->domain_aliases))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "spam_quarantine") == 0)
		     && cfg_data) {
		sett->spam_quarantine = false_true(cfg_data);
	    }    
	    else if ((strcasecmp(cfg_name, "spam_quarantine_dir") == 0)
		     && cfg_data 
		     && strcmp(cfg_data, SPAM_QUARANTINE_DIR) != 0) {
		sett->spam_quarantine_dir = 
		    (char *)realloc(sett->spam_quarantine_dir,
				    strlen(cfg_data) + 1);
		if (!sett->spam_quarantine_dir)
		    return -1;
		strcpy(sett->spam_quarantine_dir, cfg_data);
	    }

	    else if ((strcasecmp(cfg_name, "db_host") == 0)
		     && cfg_data && strcmp(cfg_data, DB_HOST) != 0) {
		sett->db_host = (char *)realloc(sett->db_host,
						strlen(cfg_data) + 1);
		if (!sett->db_host)
		    return -1;
		strcpy(sett->db_host, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "db_port") == 0) && cfg_data) {
		sett->db_port = atoi(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "db_username") == 0)
		     && cfg_data && strcmp(cfg_data, DB_USERNAME) != 0) {
		sett->db_username = (char *)realloc(sett->db_username,
						strlen(cfg_data) + 1);
		if (!sett->db_username)
		    return -1;
		strcpy(sett->db_username, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "db_password") == 0)
		     && cfg_data && strcmp(cfg_data, DB_PASSWORD) != 0) {
		sett->db_password = (char *)realloc(sett->db_password,
						strlen(cfg_data) + 1);
		if (!sett->db_password)
		    return -1;
		strcpy(sett->db_password, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "db_database") == 0)
		     && cfg_data && strcmp(cfg_data, DB_DATABASE) != 0) {
		sett->db_database = (char *)realloc(sett->db_database,
						strlen(cfg_data) + 1);
		if (!sett->db_database)
		    return -1;
		strcpy(sett->db_database, cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "restrictions") == 0) && cfg_data) {
		if (strcasecmp(cfg_data, "deny") == 0)
		    sett->restrictions = 2;	    		
		else
		    sett->restrictions = false_true(cfg_data);
	    }
	    else if ((strcasecmp(cfg_name, "scan_domains") == 0)
		&& cfg_data && (strcmp(cfg_data, SCAN_DOMAINS) != 0)) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
				 sett->scan_domains))
		    return -1;	     
	    }
	    else if ((strcasecmp(cfg_name, "not_scan_domains") == 0)
		&& cfg_data && (strcmp(cfg_data, NOT_SCAN_DOMAINS) != 0)) {
		if (split_string(SPLIT_PATTERN, cfg_data, 
				 sett->not_scan_domains))
		    return -1;	     
	    }

	}
    }

    fclose(cfg_file);
    return 0;
}


/* main routine to read config values */
int set_config(struct settings *sett, char *conf_file_user)
{
    const char *conf_dirs[] = {
	CGPRO_SETTINGS,
    	"/var/CommuniGate/Settings",
	"/var/CommuniGate",
	"/etc",
	NULL /* NULL is always the last element */
    };
    int i = 0;
    char *conf_file = NULL;
    int config_status = 0;


    if (load_defaults(sett))
	return -1;

    /* try to load user defined conf file */
    if (conf_file_user) {
	conf_file = strdup(conf_file_user);
	if (!conf_file)
	    return -1;

	config_status = read_config(conf_file, sett);
	if (conf_file)
	    free(conf_file);
	if (config_status == 0)
	    return 0;
    }

    for (i = 0; conf_dirs[i] != NULL; i++) {
	if (conf_dirs[i]) {
	    conf_file = (char *)malloc(strlen(conf_dirs[i]) + 1
				       + strlen(CGPAV_CONF) + 1);
	    if (!conf_file)
		return -1;
	    sprintf(conf_file, "%s/%s", conf_dirs[i], CGPAV_CONF);
	    config_status = read_config(conf_file, sett);
	    if (conf_file)
		free(conf_file);
	    if (config_status == 0)
		break;
	}
    }
    return 0;
}


/* destructor: free strings in the settings structure */
int free_config(struct settings *sett)
{

    if (sett->antivirus_email)
	free(sett->antivirus_email);
    if (sett->infected_header)
	free(sett->infected_header);        
    if (sett->not_infected_header)
	free(sett->not_infected_header);        
    if (sett->postmaster_account)
	free(sett->postmaster_account);
    if (sett->virtual_domains)
	free_vector(sett->virtual_domains);
    if (sett->virtual_postmaster_account)
	free(sett->virtual_postmaster_account);
    if (sett->local_networks)
	free_ip_vector(sett->local_networks);
    if (sett->local_domains)
	free_vector(sett->local_domains);
    if (sett->fake_virus_strings)
	free_vector(sett->fake_virus_strings);
    if (sett->cgpro_home)
	free(sett->cgpro_home);
    if (sett->cgpro_submitted)
	free(sett->cgpro_submitted);
    if (sett->tmp_dir)
	free(sett->tmp_dir);
    if (sett->avpctl_filename)
	free(sett->avpctl_filename);
    if (sett->sophos_socket)
	free(sett->sophos_socket);
    if (sett->clamd_socket)
	free(sett->clamd_socket);
    if (sett->trophie_socket)
	free(sett->trophie_socket);
    if (sett->drwebd_socket)
	free(sett->drwebd_socket);
    if (sett->infected_extensions)
	free_vector(sett->infected_extensions);
    if (sett->virus_quarantine_dir)
	free(sett->virus_quarantine_dir);	    	
    if (sett->virus_collection_dir)
	free(sett->virus_collection_dir);	
    
    if (sett->viruses_dir)
	free(sett->viruses_dir);	
    if (sett->charset)
	free(sett->charset);
    if (sett->sender_subject)
	free(sett->sender_subject);
    if (sett->recipient_subject)
	free(sett->recipient_subject);
    if (sett->own_text)
	free(sett->own_text);

    if (sett->spamassassin_socket)
	free(sett->spamassassin_socket);
    if (sett->spamassassin_host)
	free(sett->spamassassin_host);

    if (sett->spam_header)
	free(sett->spam_header);
    if (sett->antispam_message)
	free(sett->antispam_message);
    if (sett->domain_aliases)
	free_nameval_vector(sett->domain_aliases);
    if (sett->spam_quarantine_dir)
	free(sett->spam_quarantine_dir);	    	

    if (sett->db_host)
	free(sett->db_host);
    if (sett->db_username)
	free(sett->db_username);
    if (sett->db_password)
	free(sett->db_password);
    if (sett->db_database)
	free(sett->db_database);

    if (sett->scan_domains)
	free_vector(sett->scan_domains);
    if (sett->not_scan_domains)
	free_vector(sett->not_scan_domains);


    return 0;
}
