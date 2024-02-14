/* $Id: commoncomm.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "commoncomm.h"

/* max chars cgpro input from the filter */
#define CGPRO_INPUT_LEN 4096


/* connect to the control socket and return its filedescriptor */	
int connect_socket(char *path)
{
    int fd = -1;		/* temporary filedescriptor */
    struct sockaddr_un s;

    memset(&s, 0, sizeof(s));	/* clean struct */

    if (!path || *path == '\0')
	return -1;

    if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1)
	return -1;

    s.sun_family = AF_UNIX;
    strncpy(s.sun_path, path, sizeof(s.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&s, sizeof(struct sockaddr_un)) == -1) {
	/* unable to connect to the daemon daemon */
	close(fd);
	fd = -1;
    }

    return fd;
}

/* connect to the TCP socket and return its filedescriptor */	
int connect_tcp(char *host, int port)
{

    int fd = -1;		/* temporary filedescriptor */
    struct sockaddr_in s;
    struct hostent *hostinfo;

    memset(&s, 0, sizeof(s));	/* clean struct */

    if (!host || !port)
	return -1;

    if ((fd = socket(PF_INET, SOCK_STREAM, 0)) == -1)
	return -1;

    s.sin_family = AF_INET;
    
    /* convert host address */
    hostinfo = gethostbyname(host);
    if (!hostinfo)
	return -1;
    s.sin_addr = *((struct in_addr *)hostinfo->h_addr);
    s.sin_port = htons(port);

    if (connect(fd, (struct sockaddr *)&s, sizeof(struct sockaddr_in)) == -1) {
	/* unable to connect to the daemon */
	close(fd);
	fd = -1;
    }

    return fd;
}


/* close connection to av */
void av_disconnect(int fd)
{
    if (fd != -1)
	close(fd);
    return;
}

/* translate some chars and print message in the cgpro format */
static void tr_message(char *message, unsigned long msg_len)
{
    unsigned long i = 0;

    if (!message)
	return;
    

    for (i = 0; i < msg_len; i++) {
#ifdef AVP
	/* remove some unnecessary information */
	if (message[i] == '[') {
	    while (message[i] != ']')
		i++;
	}
#endif
	switch (message[i]) {
	case '\r':
	    fputs("\\r", stdout);
	    break;
	case '\n':
	    fputs("\\n", stdout);
	    break;
	case '\t':
	    fputs("\\t", stdout);
	    break;
	case '\\':
	    fputs("\\\\", stdout);
	    break;
	case '\"':
	    fputs("\\\"", stdout);
	    break;
	case '\'':
	    fputs("\\\'", stdout);
	    break;
#ifdef AVP
	case '/':
	    /* delete additional slashes */
	    if (!((i + 1 < msg_len) && (message[i + 1] == '[')))
		fputs("/", stdout);
	    break;
	case ']':
	    if ((i + 1 < msg_len) && (message[i + 1] == '/'))
		i++;
	    break;
#endif	    
	default:
	    fputc(message[i], stdout);
	}
    }
}



#ifdef UNMIME_LIB
/* procedure to extract and scan attachments */
static int unmime_file(MESSAGE *mess, char *filename)
{
    uulist *item;
    int i, res;
    int scan_result = 0;
    int have_virus = 0;

    if (!mess || !filename || (*filename == '\0'))
	return -1;

    if ((UUInitialize()) != UURET_OK) {
#ifdef DEBUG    
	printf("could not initialize UU\n");
#endif
	return -1;
    }

    if ((res = UULoadFile(filename, NULL, 0)) != UURET_OK) {
#ifdef DEBUG
	printf("could not load %s: %s\n",
		     filename, (res == UURET_IOERR) ?
		     strerror(UUGetOption(UUOPT_ERRNO, NULL, NULL, 0)) :
		     UUstrerror(res));
#endif
    }

    for (i = 0; (item = UUGetFileListItem(i)) != NULL; i++) {
	if ((item->state & UUFILE_OK) == 0)
	    continue;

/* Clamav now can check files in the cgpro format 
   But we still have to check extensions */
#ifndef CLAMAV
	/* use temporary file to store attachment */
	if ((res = UUDecodeToTemp(item)) != UURET_OK) {
#ifdef DEBUG
	    printf("error decoding %s: %s\n",
			 (item->filename == NULL) ? "oops" : item->filename,
			 (res == UURET_IOERR) ?
			 strerror(UUGetOption(UUOPT_ERRNO, NULL, NULL, 0)) :
			 UUstrerror(res));
#endif
	}
	else {
#ifdef DEBUG
	    printf("Attachment decoded '%s', Tmp file '%s'\n",
			 item->filename, item->binfile);
#endif

	    scan_result = is_infected(mess, item->filename, item->binfile);
    	    
            /* check if the attached file extension is suspicious */
            if (scan_result == 0)
                scan_result = check_extension(mess, item->filename);
            
	    if (scan_result)
		have_virus = 1;
	    
	    /* we don't need temporary file now */
	    UURemoveTemp(item);

	}
#else /* ifndef CLAMAV */
	scan_result = check_extension(mess, item->filename);	
	if (scan_result)
	    have_virus = 1;
#endif	
    }

    UUCleanUp();

    return have_virus;
}

/* check if the file extension is suspicious */
int check_extension(MESSAGE *mess, char *filename)
{
    char *ext = NULL;
    char *susp_file = NULL;
    int i = 0;

    if (!filename || !sett->infected_extensions 
	|| (sett->infected_extensions->size <= 0))
        return 0; 
    
    /* extract extension */
    if ((ext = strrchr(filename, '.')) && (strlen(ext) >= 2)) {
	/* compare to each extension */
	for (i = 0; i < sett->infected_extensions->size; i++) {
    	    if (strcasecmp(sett->infected_extensions->val[i], ext) == 0) {
        	susp_file = (char *)malloc(strlen("Suspicious File: ") +
                                    	   strlen(filename) + 1);
        	if (!susp_file)
            	    return 1;                               
        	sprintf(susp_file, "Suspicious File: %s", filename);
            
        	create_av_message(mess, filename, susp_file, "");
        	if (susp_file)
            	    free(susp_file);
        	return 1;
    	    }    
	}
    }	

    return 0;
}
#endif /* UNMIME_LIB */


#ifndef NO_ANTIVIRUS
int create_av_message(MESSAGE *mess, char *filename, 
		      char *virusname, char *description)
{
    char *ptr = NULL;

    if (!mess || !filename || !virusname)
        return -1;
        
    /* create detailed message with the virus filenames */
    /* first virus to be found */
    if (!mess->av_message) {
        mess->av_message = (char *)malloc(strlen(filename) + 2
						 + strlen(description) + 1
						 + strlen(virusname) + 1 + 1);
        if (!mess->av_message)
	    return -1;
            
        sprintf(mess->av_message, "%s\t\t%s %s\n", 
		filename, description, virusname);
    }
    else {
	if (!(ptr = strdup(mess->av_message)))
	    return -1;
	if (!(mess->av_message = 
	    (char *)realloc(mess->av_message,
			    + strlen(mess->av_message)
			    + strlen(filename) + 1
			    + strlen(description) + 2
			    + strlen(virusname)
			    + 1 + 1))) {
	    if (ptr)
	        free(ptr);
	    return -1;
	}
	sprintf(mess->av_message, "%s%s\t\t%s %s\n", 
		ptr, filename, description, virusname);

    }
    
    /* store the name of the virus in the vector */
    if (push_back_vector(mess->viruses, virusname))
	return -1;

    return 0;
}


/* this procedure prints out report */
void av_say_message(MESSAGE *mess)
{
    int msg_len = 0;
    

    if (!mess->av_message || !mess->virus_names) {
	fputs("\n", stdout);
	return;    
    }	

#ifdef AVP
    /* remove the filename string from avp_message */
    clear_string(mess->filename, &mess->av_message);
    clear_string("archive: Mail", &mess->av_message);
#endif


    /* create report */
    fputs(" \"\\nWARNING! Your message was infected ", stdout);

    if (mess->viruses->size > 1)
	fputs("by VIRUSES:\\n", stdout);
    else
	fputs("by VIRUS:\\n", stdout);

    fputs(mess->virus_names, stdout);
    fputs("\\n\\n", stdout);

    fputs("It was rejected for delivery.\\n\\n"
	  "Antiviral program output:\\n"
	  "==================================================\\n", stdout);

    msg_len = strlen(mess->av_message);

    /* as cgpro input is limited to 4096 characters */
    if (msg_len > (CGPRO_INPUT_LEN - 500))
	msg_len = (CGPRO_INPUT_LEN - 500);
    
    /* translate some bad chars and print the message in the cgpro format */
    tr_message(mess->av_message, msg_len);

    fputs("==================================================\\n\\n\"\n",
	  stdout);

    return;
}

/* copy infected messages to the virus quarantine and collection */
int copy_infected(MESSAGE *mess, char *filename, char *virus_name)
{
    char *tmp = NULL;
    char *outfile = NULL;
    char *ptr = NULL;
    int i = 0;
    int j = 0;


    if (!mess || (mess->viruses->size < 1) || !filename || !virus_name)
	return -1;

    /* add a virus to the virus collection */
    if (sett->virus_collection && sett->virus_collection_dir
	/* don't write to the root dir */
	&& (strlen(sett->virus_collection_dir) > 2)) {

	/* work on a copy */
	tmp = strdup(virus_name);
	if (!tmp)
	    return -1;
    
	/* remove and change some bad chars unallowed in file paths */ 
	clear_string(" ", &tmp);
	tr_string(&tmp, '/', '.');
	tr_string(&tmp, ',', '_');

	if (!(outfile = (char *)malloc(strlen(sett->virus_collection_dir) + 1 
				       + strlen(tmp) + 1)))
	    return -1;			       	
    
	strcpy(outfile, sett->virus_collection_dir);
	strcat(outfile, "/");
	strncat(outfile, tmp, 256);
    
	copy_file(filename, outfile);

#ifdef DEBUG
    printf("Virus: %s saved to collection as: %s\n", virus_name, outfile); 
#endif

	if (outfile)
	    free(outfile);
	if (tmp)
	    free(tmp);
    }	    

    /* don't copy some viruses with fake From: address */ 
    if (sett->fake_virus_strings->size > 0) {
	for (j = 0; j < sett->fake_virus_strings->size; j++) {
	    for (i = 0; i < mess->viruses->size; i++) {
		if (strstr(mess->viruses->val[i], 
			   sett->fake_virus_strings->val[j])) {	   
#ifdef DEBUG
		    printf("Virus: %s wasn't saved to quarantine as it has the fake string '%s'\n", 
			virus_name, sett->fake_virus_strings->val[j]); 
#endif
		    return 0;	   
		}    
	    }
	}
    }

    /* copy a virus to quarantine dir */
    if (sett->virus_quarantine && sett->virus_quarantine_dir
	&& (strlen(sett->virus_quarantine_dir) > 2)) {


	/* find only the filename without dir */	
	if ((ptr = strrchr(mess->filename, '/')))
	    ptr++;    
	else
	    return -1;	

	
	if (!(outfile = (char *)malloc(strlen(sett->virus_quarantine_dir) + 1 
	    + strlen(ptr) + strlen(".msg") + 1)))
	    return -1;			       	
    
	sprintf(outfile, "%s/%s.msg", sett->virus_quarantine_dir, ptr);
	    
	copy_file(mess->filename, outfile);

#ifdef DEBUG
	printf("Virus: %s saved to quarantine as: %s\n", virus_name, outfile); 
#endif

	if (outfile)
	    free(outfile);    
    }

    return 0;
}


/* main virus scanning procedure */
int av_scan_file(MESSAGE *mess)
{
    int response = 0;
    int response_attach = 0; 
    int i = 0;
    int j = 0;
    

    if (!mess->filename || *(mess->filename) == '\0')
	return 0;

    openlog("cgpav", 0, sett->log_facility);	/* start logging */

    mess->av_message = NULL;
    mess->virus_names = NULL;	
    /* there can be many viruses , so we use a vector */
    mess->viruses = (char_vector *)malloc(sizeof(char_vector));
    if (!mess->viruses)
        return -1;
    mess->viruses->val = NULL;
    mess->viruses->size = 0;
            
    /* check the message file */
    response = is_infected(mess, "", mess->filename);

#ifdef UNMIME_LIB    
    /* unmime and scan attachments in the message */
    response_attach = unmime_file(mess, mess->filename);
#endif    

    /* everything is OK */
    if ((response == 0) && (response_attach == 0)) 
	return 0;
    /* some error */	
    else if ((response == -1) || (response_attach == -1)) 
    	return -1;
    /* timeout */	
    else if ((response == -2) || (response_attach == -2)) 
    	return -2;
    
    /* virus has been found */
    /* virus names in one string, comma separated */
    if (!mess->virus_names) {
	mess->virus_names = join_vector(", ", mess->viruses);	
	if (!mess->virus_names)
	    return 1;
    }

    /* comma separated list in one string */
    mess->recipient_names = join_vector(", ", mess->recipients);
    if (!mess->recipient_names)
	return 1;    

    
    if (mess->virus_names && mess->sender && mess->recipient_names) {
	/* if the virus sender's IP address found */
	if (mess->smtp) {
	    syslog(LOG_ERR, "Virus: %s  From: %s  To: %s IP: %s", 
		mess->virus_names, mess->sender, mess->recipient_names,
		my_ntoa(mess->smtp));			
	}
	else {
	    syslog(LOG_ERR, "Virus: %s  From: %s  To: %s", 
		mess->virus_names, mess->sender, mess->recipient_names);			
	}
    }

    /* if we don't want to send notifications about some viruses (worms) */
    /* still send notifications to the local users */
    if (!mess->is_sender_local 
	&& sett->virus_name_notification && (mess->viruses->size > 0) 
	&& (sett->fake_virus_strings->size > 0)) {
	for (j = 0; j < sett->fake_virus_strings->size; j++) {
	    for (i = 0; i < mess->viruses->size; i++) {
		if (strstr(mess->viruses->val[i], 
			   sett->fake_virus_strings->val[j]))
		    /* discard message without sending notification */	   
		    return 2;	   
	    }
	}
    }

    return 1;
}

/* destructor */
void free_av_scan_file(MESSAGE *mess)
{
    if (mess->fd != -1)
	av_disconnect(mess->fd);

    if (mess->av_message)
	free(mess->av_message);
    mess->av_message = NULL;

    if (mess->viruses)
	free_vector(mess->viruses);

    if (mess->virus_names)
	free(mess->virus_names);
    mess->virus_names = NULL;	

    if (mess->recipient_names)
	free(mess->recipient_names);
    mess->recipient_names = NULL;	
        	
}

#endif /* NO_ANTIVIRUS */


/* =============== SPAMASSASSIN ============================= */
#ifndef NO_SPAMASSASSIN

/* copy spam into quarantine dir */
int copy_spam(MESSAGE *mess)
{
    char *outfile = NULL;
    char *ptr = NULL;


    /* copy spam to the quarantine dir */
    if (!sett->spam_quarantine 
	|| !mess || !mess->filename
	|| !sett->spam_quarantine_dir 
	|| (strlen(sett->spam_quarantine_dir) < 2)) 
	return 0;

	
    /* find only the filename without dir */	
    if ((ptr = strrchr(mess->filename, '/')))
	ptr++;    
    else
	return -1;	
    		
	    
    if (!(outfile = (char *)malloc(strlen(sett->spam_quarantine_dir) + 1 
	+ strlen(ptr) + strlen(".msg") + 1)))
	return -1;			       	
    
    sprintf(outfile, "%s/%s.msg", sett->spam_quarantine_dir, ptr);
    
    copy_file(mess->filename, outfile);

#ifdef DEBUG
    printf("Spam saved into quarantine as: %s\n", outfile); 
#endif

    if (outfile)
	free(outfile);    
	

    return 0;
}


/* print different answers */
static void spam_action(MESSAGE *mess, int action)
{
    int spam_level = 0;
    int is_spam = 0;

    if (!mess)
	return;

    switch (action) {
    /* action reject */
    case 2:
	/* create an undeliverable message about spam */
	printf("%s ERROR \"\\n", mess->seqnum);
	tr_message(sett->antispam_message, strlen(sett->antispam_message));
	printf("\"\n");
	break;
    /* action discard */
    case 3:
	/* discard message */
	printf("%s DISCARD\n", mess->seqnum);
	break;
    /* action addheader */
    case 4:
    case 5:
    /* action addheaderall */
    case 6:
	if (mess->spam_score >= mess->spam_threshold)
	    is_spam = 1;

	printf("%s ADDHEADER ", mess->seqnum);
	printf("\"X-Spam-Status: ");
	
	if (is_spam)    
	    printf("Yes");
	else
	    printf("No");
	        
	printf(", hits=%.1f required=%.1f", 
	    mess->spam_score, mess->spam_threshold);
	       
	/* print tests description */       
	if (mess->spam_message) {
	    printf(" tests=");
	    tr_message(mess->spam_message, strlen(mess->spam_message));
	}       

	/* additional header */
	if (is_spam && sett->spam_header && (strlen(sett->spam_header) > 3)) {
	    printf("\\n");
	    tr_message(sett->spam_header, strlen(sett->spam_header));
	}
	    
	/* add the header X-Spam-Level:  */
	if (sett->spam_level_header) {
    	    spam_level = (int)mess->spam_score;
	    if (spam_level > 30)
		spam_level = 30;
    	    /* number of * chars indicates the spam_score */
    	    if (spam_level >= 1) {
		if (spam_level > 35)
		    spam_level = 35;
    		fputs("\\nX-Spam-Level: ", stdout);
		for ( ; spam_level > 0; spam_level--)
    		    fputc(sett->spam_level_char, stdout);
	    }
	    fputs("\\n", stdout);
	}    
	
	printf("\"\n");
	break;
    /* action addheaderjunk */
    case 7:
	printf("%s ADDHEADER ", mess->seqnum);
	/* add the header X-Junk-Score */
	printf("\"X-Junk-Score: %.1f [", mess->spam_score);
	    
	spam_level = (int)mess->spam_score;
	if (spam_level >= 1) {
	    if (spam_level > 30) {
	        spam_level = 30;
	    }
	    for (; spam_level > 0; spam_level--) {
	        fputc('X', stdout);
	    }
	}
	printf("]\\n");
	    
	/* print the test description */
	if (mess->spam_message) {
	    printf("X-Junk-Tests: ");
	    tr_message(mess->spam_message, strlen(mess->spam_message));
	}
	    
	printf("\"\n");
	break;
    /* action "addheaderalljunk" */
    case 8:
	if (mess->spam_score >= mess->spam_threshold)
	    is_spam = 1;

	printf("%s ADDHEADER ", mess->seqnum);

	/* add the header X-Junk-Score */
	if (is_spam) {
	  printf("\"X-Junk-Score: %.1f [", mess->spam_score);
	
	  spam_level = (int)mess->spam_score;
	  if (spam_level >= 1) {
	      if (spam_level > 30) {
	          spam_level = 30;
	      }
	      for (; spam_level > 0; spam_level--) {
	          fputc('X', stdout);
	      }
	  }
	  printf("]\\n");
	
	  /* print the test description */
	  if (mess->spam_message) {
	      printf("X-Junk-Tests: ");
	      tr_message(mess->spam_message, strlen(mess->spam_message));
	  }
	}

	/* add the header X-Spam-Status:  */
	
	if (is_spam)
	    printf("\\nX-Spam-Status: Yes");
	else
	    printf("\"X-Spam-Status: No");
	
	printf(", hits=%.1f required=%.1f",
	    mess->spam_score, mess->spam_threshold);
	
	/* print tests description */
	if (mess->spam_message) {
	    printf(" tests=");
	    tr_message(mess->spam_message, strlen(mess->spam_message));
	}

	/* additional header */
	if (is_spam && sett->spam_header && (strlen(sett->spam_header) > 3)) {
	    printf("\\n");
	    tr_message(sett->spam_header, strlen(sett->spam_header));
	}
	
	/* add the header X-Spam-Level:  */
	if (sett->spam_level_header) {
    	    spam_level = (int)mess->spam_score;
	    if (spam_level > 30)
		spam_level = 30;
    	    /* number of * chars indicates the spam_score */
    	    if (spam_level >= 1) {
		if (spam_level > 35)
		    spam_level = 35;
    		fputs("\\nX-Spam-Level: ", stdout);
		for ( ; spam_level > 0; spam_level--)
    		    fputc(sett->spam_level_char, stdout);
	    }
	    fputs("\\n", stdout);
	}
	
	printf("\"\n");
	break;
    /* action none */
    case 0:
    default:
	/* add the header indicating that the message was scanned */
	if (sett->add_not_infected_header 
	    && (strlen(sett->not_infected_header) > 2)) {
		printf("%s ADDHEADER \"%s\"\n", mess->seqnum,
			sett->not_infected_header);
	}
	else {
	    sett->add_not_infected_header = 0;
	    printf("%s OK\n", mess->seqnum);
	}	    
    }
}

#ifndef NO_DB
/* convert domain aliases from e-mails */
static int convert_domain_aliases(char **str)
{
    int i = 0;    
    char *ptr = NULL;

    if ((sett->domain_aliases <= 0) || !str)
	return -1;

    for (i = 0; i < sett->domain_aliases->size; i++) {
	if ((ptr = strchr(*str, '@'))) {
	    ptr++;
    	    if (strcasecmp(sett->domain_aliases->val[i]->name, ptr) == 0)  {
#ifdef DEBUG
		printf("Alias found: %s=>", *str);
#endif			
		string_replace(sett->domain_aliases->val[i]->name,
			       sett->domain_aliases->val[i]->val, str);	
#ifdef DEBUG
		printf("%s\n", *str);
#endif					       
		break;	       
	    }
	    
	}    
    }

    return 0;
}
#endif /* NO_DB */

/* scan the message for spam */
int spam_scan_file(MESSAGE *mess)
{
    int response = 0;
    int i = 0;
    
    if (!mess || !mess->filename)
	return -1;        
    
    if (!sett->spam_action || !sett->enable_spamassassin) {
	spam_action(mess, 0);
	return 0;    
    }	

    /* avoid warnings */
    i = 0;
    
    /* don't scan if the sender is local */
    if (!sett->spam_scan_local && mess->is_sender_local) {
#ifdef DEBUG
	printf("Don't scan for spam - the sender is local\n");
#endif    
	spam_action(mess, 0);
	return 0;    
    }
    
#ifndef NO_DB
    /* convert aliases */
    for (i = 0; i < mess->recipients->size; i++)
	convert_domain_aliases(&mess->recipients->val[i]);

    /* try to find if there is a user (one of the recipients) 
     * in the database with SpamAssassin settings */
    get_db_user(mess);

    if (mess->user && (mess->user_spam_action == 0)) {
#ifdef DEBUG	
	printf("The user %s disabled spam scanning\n", mess->user);
#endif
	spam_action(mess, 0);
	return 0;
    }    
#endif /* NO_DB */        

    /* spam detection */
    response = is_spam(mess);

    switch (response) {
	/* all is OK */
	case 0:
	/* add the X-Spam-Status header indicating spam to all messages */
	if (((sett->spam_action == 6 || sett->spam_action == 8) 
	     /* the user hasn't defined any action */
	     && (!mess->user_spam_action
	     /* the user delegated spam action decision to admin */
	     || (mess->user_spam_action == 1)))
	    /* addheaderall user action */
	    || (mess->user_spam_action == 6 || mess->user_spam_action == 8)) {
	    spam_action(mess, sett->spam_action);
	    break;
	}	
	/* timeout in scanning */
	case -2:
	    spam_action(mess, 0);
	    break;
	/* default action on spam detection */
	case 1:
	    /* if the user has his own action on spam detection */
	    if (mess->user_spam_action)
		spam_action(mess, mess->user_spam_action);
	    else if (!sett->extra_spam_action 
		     || (mess->spam_score < sett->extra_spam_score))
		spam_action(mess, sett->spam_action);
	    /* if the spam_score is extra high */
	    else 
		spam_action(mess, sett->extra_spam_action);
	
	    /* make a copy */
	    if (sett->spam_quarantine)
		copy_spam(mess);	
	    break;
	case -1:
	    return -1;
	default:
	    spam_action(mess, 0);
    }	

    return response;
}

/* destructor */
void free_spam_scan_file(MESSAGE *mess)
{
    if (mess->fd != -1)
	av_disconnect(mess->fd);

    if (mess->spam_message)
	free(mess->spam_message);
    mess->spam_message = NULL;

    if (mess->user)
	free(mess->user);
    mess->user = NULL;	

}

#endif /* NO_SPAMASSASSIN */


