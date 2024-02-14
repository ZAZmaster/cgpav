/* $Id: avpcomm.c, v 1.4 2005/07/01 12:00:00 farit Exp $ */

#include "avpcomm.h"


/* get virus names from the AVP response */
int get_virus_names(MESSAGE *mess)
{
    char *p = NULL;
    char *vir = NULL;
    char *tmp = NULL;


    if (!mess->av_message || !(tmp = strdup(mess->av_message)))
	return -1;

    p = strtok(tmp, "\n");
    
    while (p) {
	if ((vir = strstr(p, "infected"))
	    /* that's "infected" on Russian */
	    || (vir = strstr(p, "заражен"))) {
	    vir = strchr(vir, ':') + 1;
	    p = vir + strlen(vir) - 1;

	    /* remove trailing and beginning spaces */
	    while ((isspace((int)*p)) && (p >= vir)) {
		*p-- = '\0';
	    }
	    while (isspace((int)*vir))
		vir++;

	    /* store the virus name into the vector */
	    if (push_back_vector(mess->viruses, vir))
		return -1;
	}
	p = strtok(NULL, "\n");
    }

    if (tmp)
	free(tmp);

    return 0;
}


/* main scanning procedure */
/* 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename)
{
    char *request = NULL;
    time_t now = time(NULL);
    int response = 0;
    unsigned long msg_len = 0;
    int read_len = 0;
    char *msg_ptr = NULL;


    if (!mess || !filename || (*filename == '\0'))
	return 0;


    /* connect to avpd */
    if (!sett->avpctl_filename)
	return -1;		/* can't connect to the avp socket */

    if ((mess->fd = connect_socket(sett->avpctl_filename)) == -1) {
#ifdef DEBUG
    printf("ERROR! Can't connect to the AVP daemon socket: %s\n"
	   "Check avpctl_filename in cgpav.conf\n", 
	    sett->avpctl_filename);	    
#endif
	return -1;	/* error connecting to the avp socket */
    }

    /* prepare the avpd command */
    if (!(request = (char *)malloc(28 + strlen(filename))))
	return -1;	/* error allocating memory */

    sprintf(request, "<0>%.15s:\xfeI0|o{%s}\xfe", ctime(&now) + 4, filename);
    if (write(mess->fd, request, strlen(request)) != strlen(request)) {
	if (request)
	    free(request);
	return -1;	/* error writing to avp socket */
    }

    if (request)
	free(request);

    if (timeout_read(sett->av_timeout, mess->fd, (char *)&response, 2) < 2)
	return -2;	/* unable to read avp response, timeout */

/* Sun Sparc Solaris */
#ifdef SOLARIS
    /* move bits to make 0x134 from 0x1340000 and 0x130 from 0x1300000 */
    response >>= 16;

#endif

/* uncomment strings below to see AVP response code */
/*  printf("AVP response: %x, Response with mask: %x\n", 
           response, response & 0xcf); */

    switch (response & 0xcf) {
    case 0x40:			/* key file not found or has expired */
	syslog(LOG_ERR, "KAV's key file not found or has expired");
    case 8:			/* file is corrupted */
    case 7:			/* avp daemon is corrupted */
    case 6:			/* virus(es) deleted */
    case 5:			/* virus(es) disinfected */
    case 1:			/* virus scan hasn't been completed */
    case 0:			/* file is OK */
	return 0;
    case 4:			/* virus(es) detected */
    case 3:			/* suspicious object */
    case 2:			/* corrupted or changed virus */
	break;
    default:			/* unknown result code */
	return -1;
    }

    /* is there some messages from avp daemon? */
    if (!(response & 0x0100))	/* no messages */
	return 1;	/* there was a virus */


    /* now it's time to read in avp's report */
    if (timeout_read(sett->av_timeout, mess->fd, (char *)&msg_len, 4) != 4) {
	/* unable to read avp response */
	return 1;	/* there was a virus */
    }

    /* allocate enough space for the message */
    mess->av_message = (char *)malloc(msg_len + 1);

    if (!mess->av_message)
	return 1;	/* there was a virus */

    msg_ptr = mess->av_message;

    while (msg_len && (read_len = 
	timeout_read(sett->av_timeout, mess->fd, msg_ptr, msg_len)) > 0) {
	msg_ptr += read_len;
	msg_len -= read_len;
    }

    if (msg_len || read_len < 0)	/* unable to read avp response */
	return 1;	/* there was a virus */

    *msg_ptr = '\0';		/* don't forget to set end of msg */

    if (mess->fd != -1)
	av_disconnect(mess->fd);

    /* try to get virus names */
    get_virus_names(mess);

    return 1;
}


