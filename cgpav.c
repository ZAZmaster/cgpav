/* AntiVirus and AntiSpam External Filter for CommuniGate Pro
 * Copyright (c) 2010 Damir Bikmuhametov, Farit Nabiullin
 * $Id: cgpav.c, v 1.5 2010/07/01 12:00:00 farit Exp $
 * www: http://program.farit.ru
*/

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_SYS_TIME_H
#include <sys/time.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

#include "config.h"
#include "cfg.h"

#include "commoncomm.h"
#include "email.h"
#include "util.h"
#include "xsignal.h"


/* === DEFINES ============================================================= */
#define API_INTERFACE_VERSION 2		/* version of the filtering API */
#define MAX_INPUT_LEN 4096		/* max length of input string */
#define INPUT_BUFSIZE 2048		/* max length of the header string */

/* === VARIABLES =========================================================== */
int childs = 0;			/* current number of childs */
int requests_pending = 0;	/* current number of requests */
MESSAGE *queue = NULL;		/* request queue */
char *filename = NULL;		/* filename to check */
char *seqnum = NULL;		/* sequence number */
char *conf_file = NULL;		/* configuration file */
static char *seqnum_alarm = NULL;	/* sequence number for handling timeout */
static int error_counter = 0;	/* number of errors while virus scanning */
struct settings *sett;		/* structure to store settings */

/* === FUNCTIONS =========================================================== */

/* check if we must scan this domain */
int scan_domain(MESSAGE *mess);
static void free_message(MESSAGE *mess);
void queue_add_entry(char *, char *);
void queue_delete_entry(pid_t);
MESSAGE *queue_get_next_entry(void);
void queue_tidy(void);
int queue_count(void);
void dispatch_request(void);
static void chld(int);
void catch_timeout(int sig);


/* check if we must scan this domain */
/* 0 - scan, 1 don't scan */
int scan_domain(MESSAGE *mess)
{
    int i = 0;
    int j = 0;
    
    if (!mess)
	return -1;

    if (!sett->restrictions)
	return 0;

    /* white list */
    if (sett->restrictions == 1) {
	for (i = 0; i < sett->scan_domains->size; i++) {
	    for (j = 0; j < mess->domains->size; j++) {
		if (strcasecmp(sett->scan_domains->val[i],
			       mess->domains->val[j]) == 0)	
		    return 0;
    	    }
	}
	return 1;
    }
    /* black list */
    else if (sett->restrictions == 2) {
	for (i = 0; i < sett->not_scan_domains->size; i++) {
	    for (j = 0; j < mess->domains->size; j++) {
		if (strcasecmp(sett->not_scan_domains->val[i],
			       mess->domains->val[j]) == 0)	
		    return 1;
    	    }
	}
    }

    return 0;	    
}

static void free_message(MESSAGE *mess)
{
    if (!mess)
	return;

    if (mess->seqnum)
	free(mess->seqnum);
    if (mess->filename)
	free(mess->filename);
    if (mess->av_message)
	free(mess->av_message);
    if (mess->viruses)
	free_vector(mess->viruses);
    if (mess->virus_names)
	free(mess->virus_names);
    if (mess->spam_message)
	free(mess->spam_message);
    if (mess->user)
	free(mess->user);
    if (mess->sender)
	free(mess->sender);	
    if (mess->recipients)
	free_vector(mess->recipients);		    
    if (mess->domains)
	free_vector(mess->domains);	

    free(mess);
}

/* adds entry to the queue */
void queue_add_entry(char *seqnum, char *filename)
{
    MESSAGE *ptr = NULL;
    MESSAGE *ptr2 = NULL;

    if (!seqnum || *seqnum == '\0')
	return;
    if (!filename || *filename == '\0')
	return;

    if (!(ptr = (MESSAGE *)malloc(sizeof(MESSAGE)))) {
	printf("%s REJECTED \"Can't allocate memory for object.\"\n", seqnum);
	fflush(stdout);
	syslog(LOG_ERR,
	       "Can't allocate memory for object. Rejecting message: %s",
	       filename);
	return;
    }

    if (!(ptr->seqnum = strdup(seqnum))) {
	free(ptr);
	printf("%s REJECTED \"Can't allocate memory for object.\"\n", seqnum);
	fflush(stdout);
	syslog(LOG_ERR,
	       "Can't allocate memory for object. Rejecting message: %s",
	       filename);
	return;
    }

    if (!(ptr->filename = strdup(filename))) {
	free(ptr->seqnum);
	free(ptr);
	printf("%s REJECTED \"Can't allocate memory for object.\"\n", seqnum);
	fflush(stdout);
	syslog(LOG_ERR,
	       "Can't allocate memory for object. Rejecting message: %s",
	       filename);
	return;
    }

    strcpy(ptr->filename, filename);
    
    ptr->pid = 0;
    ptr->sender = NULL;
    ptr->recipients = NULL;
    ptr->recipient_names = NULL;
    ptr->domains = NULL;
    ptr->smtp = 0;
    ptr->is_sender_local = 0;
    ptr->viruses = NULL;
    ptr->av_message = NULL;
    ptr->virus_names = NULL;
    ptr->is_spam = 0;
    ptr->spam_score = 0.0f;
    ptr->spam_threshold = 0.0f;
    ptr->spam_message = NULL;
    ptr->user_spam_action = 0;
    ptr->user = NULL;
    ptr->deleted = 0;
    ptr->next = NULL;

    if (!queue)
	queue = ptr;
    else {
	for (ptr2 = queue; ptr2->next; ptr2 = ptr2->next);
	ptr2->next = ptr;
    }

    requests_pending++;

    return;
}

/* marks processed entry for deletion */
void queue_delete_entry(pid_t pid)
{
    MESSAGE *ptr = NULL;

    if (!queue)
	return;

    for (ptr = queue; ptr; ptr = ptr->next) {
	if (ptr->pid == pid) {
	    ptr->deleted++;
	    return;
	}
    }
    return;
}

/* gets pointer to next undispatched queue entry */
MESSAGE *queue_get_next_entry(void)
{
    MESSAGE *ptr = NULL;

    if (queue)
	for (ptr = queue; ptr; ptr = ptr->next)
	    if (!ptr->pid)
		return ptr;

    return NULL;
}

/* frees deleted entries */
void queue_tidy(void)
{
    MESSAGE *ptr = NULL;
    MESSAGE *ptr2 = NULL;

    if (!queue)
	return;

    while (queue && queue->deleted) {
	ptr = queue;
	queue = queue->next;
	free_message(ptr);
    }

    if (!queue)
	return;

    for (ptr = queue; (ptr && ptr->next); ptr = ptr->next)
	if (ptr->next->deleted) {
	    ptr2 = ptr->next;
	    ptr->next = ptr2->next;
	    
	    free_message(ptr2);
	}

    return;
}

#ifdef DEBUG
/* this function counts number of queue members */
int queue_count(void)
{

    MESSAGE *ptr = NULL;
    int rc = 0;

    if (!queue)
	return rc;

    for (ptr = queue; ptr; ptr = ptr->next)
	rc++;
    return rc;
}

/* this function prints contents of queue */
void queue_print()
{
    MESSAGE *ptr = NULL;

    if (!queue) {
	printf("queue is empty\n");
	return;
    }

    for (ptr = queue; ptr; ptr = ptr->next) {
	printf("seqnum = %s, filename = %s, pid = %d, deleted = %d\n",
	       ptr->seqnum, ptr->filename, ptr->pid, ptr->deleted);
    }
    return;
}
#endif


/* process next request from queue */
void dispatch_request(void)
{
    MESSAGE *mess = NULL;		/* currently dispatched entry */
    pid_t pid;				/* pid of the forked process */
    int av_status = 0;			/* is av working */
    static struct sigaction act;	/* for alarm */
    int continue_scan = 1;		/* what to do after virus scanning */
    float spam_score = 0.0f;		/* counted spam score */
    float spam_threshold = 0.0f;	/* when score over it spam detected */
    int is_idle = 1;			/* flag if this call didn't do anything */

    spam_score = 0.0f;
    spam_threshold = 0.0f;
    
    
    while (requests_pending     
#ifndef SOLARIS  /* bug in Solaris with SIGCHLD */  
    && (childs < sett->max_childs)
#endif    
    ) {

	if (!(mess = queue_get_next_entry()))
	    break;		/* theoretically this shouldn't
				   happen, but in case... */
				   
/* don't fork children while in the DEBUG mode */
#ifndef DEBUG
	pid = fork();

	if (pid < 0) {
	    /* error creating child process */
	}
	else if (!pid) {
#endif	
	    /* child process begins here */

	    /* set timeout handler */
	    seqnum_alarm = strdup(mess->seqnum);
	    if (!seqnum_alarm) {
		printf("%s OK\n", mess->seqnum);
		exit(1);
	    }
	    act.sa_handler = catch_timeout;
	    sigaction(SIGALRM, &act, NULL);
	    alarm(sett->av_timeout + 10);
	    
#ifdef DEBUG
	    /* disable timeout */	    
	    alarm(0);
#endif
	    
	    /* try to extract sender's and recipients' e-mails */
	    parse_headers(mess);

	    /* if there are some restrictions in scanning domains */
	    if (sett->restrictions && scan_domain(mess)) {
#ifdef DEBUG
		printf("This message won't be scanned because of "
			"the domain restrictions\n");
#endif
		printf("%s OK\n", mess->seqnum);
		goto the_end;
	    }
	    
/* if we do not want to scan for viruses */
#ifndef NO_ANTIVIRUS
	    /* sett->infected_action = 0 means do nothing */
	    if (sett->infected_action == 0) {
		continue_scan = 1;
	    }
	    else {
		switch (av_scan_file(mess)) {
		case 0:
		    /* all is OK */
		    continue_scan = 1;
		    break;
		case 1:
		    /* a virus has been found */
		    /* discard the infected message */
		    if (sett->infected_action == 3)
			printf("%s DISCARD\n", mess->seqnum);
		    /* addheader about virus */
		    else if (sett->infected_action == 4)
			printf("%s ADDHEADER \"%s\"\n", mess->seqnum,
			       sett->infected_header);
		    /* send Undeliverable message about virus */
		    else {
			printf("%s ERROR ", mess->seqnum);
			av_say_message(mess);
		    }
		    
		    /* send additional notifications */
		    email_notifications(mess);
		    /* no spam scanning */
		    continue_scan = 0;
		    break;
		case 2:
		    /* a virus has been found */ 
		    /* discard the message */
		    printf("%s DISCARD\n", mess->seqnum);		        
		    continue_scan = 0;
		    break;
		case -1:
		    /* some error has occured. we won't
		       * lose mail, so we report "REJECTED" */
		    av_status = 1;
		    if (error_counter < sett->max_errors) {
			printf("%s REJECTED \"No connection to the Antiviral filter."
			       " Will try later.\"\n", mess->seqnum);
			syslog(LOG_ERR, "Error checking file: %s",
			       mess->filename);
			continue_scan = 0;
			break;
		    }
		case -2:
		    /* timeout in virus scanning */
		    /* this message can be annoying */		    
		    /* syslog(LOG_ERR, "Timeout checking file: %s",
			   mess->filename); */
		    continue_scan = 1;
		    break;

		default:
		    continue_scan = 1;
		}
		/* free allocated memory */	
		free_av_scan_file(mess);
	    }
#endif /* NO_ANTIVIRUS */

/* if we want to scan for spam */
#ifndef NO_SPAMASSASSIN 
	    /* spam detecting now */
	    if (continue_scan) {
		if (spam_scan_file(mess) == -1) {
		    /* some error has occured. we won't
		     * lose mail, so we report "REJECTED" */
		    av_status = 1;
		    if (error_counter < sett->max_errors) {
			printf("%s REJECTED \"No connection to the Antispam filter."
			       " Will try later.\"\n", mess->seqnum);
			syslog(LOG_ERR, "Error spam checking file: %s",
				mess->filename);
		    }
		    else 
			printf("%s OK\n", mess->seqnum);
		}
		/* free memory allocation */
		free_spam_scan_file(mess);    
	    }
#else
	    if (continue_scan) {		
		if (sett->add_not_infected_header) {
		    /* if the header was supplied */
		    if (strlen(sett->not_infected_header) > 2) {
			printf("%s ADDHEADER \"%s\"\n", mess->seqnum,
				sett->not_infected_header);
		    }
		    else {
			sett->add_not_infected_header = 0;
			printf("%s OK\n", mess->seqnum);
		    }
		}
		/* just print OK */
		else     			
		    printf("%s OK\n", mess->seqnum);	
	    }	
#endif /* SPAMASSASSIN */

the_end:    fflush(stdout);

	    /* free memory allocated for the headers */
	    free_headers(mess);
	    alarm(0);
	    
	    if (seqnum_alarm)
		free(seqnum_alarm);

	    /* return errors */ 
	    exit(av_status);

/* we don't fork children in DEBUG mode */
#ifndef DEBUG	    
	}
	else {
	    /* main program continues here */
	    mess->pid = pid;
	    childs++;
	    requests_pending--;
	    /* it worked */
	    is_idle = 0;
	}
#endif

    }	/* while */

    /* there was no response, wait a second for the other cycle */
    if (is_idle == 1) {
	sleep(1);
    }
    else {
    }	
}


/* SIGCHLD handler. it's called when child changes its status (f.e. exits) */
static void chld(int signo)
{
    int old_errno = errno;
    pid_t pid;
    int status, exit_status;

    /* catch exited children */
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
	queue_delete_entry(pid);
	childs--;

	/* check the status of the daemons */
	if (WIFEXITED(status)) {
	    exit_status = WEXITSTATUS(status);
	    if (exit_status)
		error_counter++;
	    else 
		error_counter = 0;
	}
    }

    errno = old_errno;		/* restore old errno */

    return;
}

void parse_command_line(int argc, char **argv)
{
    int c;

    while ((c = getopt(argc, argv, "f:?h")) != EOF) {
	switch (c) {
	case 'f':
	    if (optarg && *optarg) {
		if (access(optarg, R_OK) == 0) {
		    conf_file = strdup(optarg);
		    /* get rid of trailing '/' */
		    while (conf_file && *conf_file
			   && conf_file[strlen(conf_file) - 1] == '/')
			conf_file[strlen(conf_file) - 1] = '\0';
		}
		else {
		    syslog(LOG_ERR, "Can't read the config file %s", optarg);
		}
	    }
	    break;
	case 'h':		/* help requested */
	case '?':
	default:

	    printf("Anti-Virus External Filter for CommuniGate Pro "
		   "\n(C) 2002 Damir Bikmuhametov, Farit Nabiullin\n"
		   "\n"
		   "Usage: %s <options>\n"
		   "where <options> are:\n"
		   "-? or -h - this message\n"
		   "-f - configuration file\n\n"
		   "If you omit conf file name, the program will search\n"
		   "for cgpav.conf file first in /var/CommuniGate, then in /etc\n"
		   "and if it find nothing it will use the program defaults\n"
		   "\n"
		   "Examples: %s -f /var/CommuniGate/cgpav.conf \n"
		   "          %s\n", *argv, *argv, *argv);
	    exit(0);
	}			/* switch */
    }				/* while */
    return;
}


/* just print OK and exit on timeout */
void catch_timeout(int sig)
{
    printf("%s OK\n", seqnum_alarm);
    fflush(stdout);

    if (seqnum_alarm)
	free(seqnum_alarm);
    exit(1);
}


/* === MAIN PROGRAM ======================================================== */

int main(int argc, char **argv)
{
    char input_str[MAX_INPUT_LEN];	/* input buffer */
    char *char_ptr = NULL;	/* */
    char *dir_filename = NULL;
    fd_set read_mask;		/* for select() */
    struct timeval timeout;	/* for select() */


    /* initialization */
    parse_command_line(argc, argv);

    sett = (struct settings *)malloc(sizeof(struct settings));
    if (set_config(sett, conf_file))
	return -1;

    openlog("cgpav", 0, sett->log_facility);	/* start logging */

    xsignal(SIGCHLD, chld);	/* set signal handler */
    signal(SIGPIPE, SIG_IGN);	/* ignore SIGPIPE signal */


    timeout.tv_sec = 0;		/* simulate poll() with select() */
    timeout.tv_usec = 0;

    FD_ZERO(&read_mask);	/* initialize set */

    /* main cycle starts here */
    while (requests_pending || !feof(stdin)) {

	/* put stdin into set */
	FD_SET(0, &read_mask);

	/* if there are pending requests, set no timeout.
	 * otherwise wait for input endlessly */
	if (select(1, &read_mask, NULL, NULL, requests_pending 
	    ? &timeout : NULL) > 0) {

	    /* read input here */
	    if (fgets(input_str, MAX_INPUT_LEN, stdin)) {

		/* strip ending '\n' and '\r' */
		if ((char_ptr = strchr(input_str, '\r')))
		    *char_ptr = '\0';
		if ((char_ptr = strchr(input_str, '\n')))
		    *char_ptr = '\0';

		/* parse input string, put it to the queue */
		seqnum = strtok(input_str, " \t");
		char_ptr = strtok(NULL, " \t");
		filename = strtok(NULL, " \t");

		if (seqnum && char_ptr) {
		    if (filename && !strcasecmp(char_ptr, "FILE")) {
			dir_filename = (char *)malloc(strlen(sett->cgpro_home)
						      + 1 + strlen(filename)
						      + 1);
			if (dir_filename) {
			    sprintf(dir_filename, "%s/%s", sett->cgpro_home,
				    filename);
			    queue_add_entry(seqnum, dir_filename);
			    free(dir_filename);
			}
			else {
			    printf("%s REJECTED \"Can't allocate memory "
				   "for object.Will try later. \"\n", seqnum);
			    fflush(stdout);
			    syslog(LOG_ERR,
				   "Can't allocate memory for object. Rejecting message: %s",
				   filename);
			}
		    }
		    else if (filename && !strcasecmp(char_ptr, "INTF")) {
			printf("%s INTF %d\n", seqnum,
			       API_INTERFACE_VERSION);
			fflush(stdout);
		    }
		    else {
			printf("%s OK\n", seqnum);
			fflush(stdout);
		    }
		}
	    }
	}

	/* dispatch request */
	dispatch_request();

	/* tidy queue */
	queue_tidy();
	queue_tidy();

    }				/* end of the main cycle */

    /* free contents of the settings structure */
    free_config(sett);
    if (sett)
	free(sett);

    if (conf_file)
	free(conf_file);

    closelog();

    queue_tidy();

    return 0;
}
