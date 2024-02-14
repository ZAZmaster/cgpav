/* $Id: kavcomm.c, v 1.3a 2004/02/01 12:00:00 farit Exp $ */

#include "kavcomm.h"


/* main scanning procedure */
/* 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename)
{
    char *request = NULL;
    int response = 0;
    int av_code = 0;
    char buff[1024];   
    char *vir = NULL, *ptr = NULL, *ptr1 = NULL;

    memset(buff, 0, sizeof(buff));


    if (!mess || !filename || (*filename == '\0'))
	return 0;


    /* connect to the kavd */
    if (!sett->avpctl_filename)
	return -1;		/* can't connect to the aveserver socket */

    if ((mess->fd = connect_socket(sett->avpctl_filename)) == -1) {
#ifdef DEBUG
    printf("ERROR! Can't connect to the aveserver daemon socket: %s\n"
	   "Check avpctl_filename in cgpav.conf\n", 
	    sett->avpctl_filename);	    
#endif
	return -1;	/* error connecting to the avp socket */
    }
            
    /* prepare aveserver command */
    if (!(request = (char *)malloc(strlen("SCAN xmQPRSTUWabcdefghi ") 
	+ strlen(filename) + 2 + 1)))
	return -1;	/* error allocating memory */

    sprintf(request, "SCAN xmQPRSTUWabcdefghi %s\r\n", filename);
    
    if (write(mess->fd, request, strlen(request)) != strlen(request)) {
	if (request)
	    free(request);
	return -1;	/* error writing to the aveserver socket */
    }

    if (request)
	free(request);

     while (readline(sett->av_timeout, mess->fd, 
    	    (char *)&buff, sizeof(buff)) > 0) {
            
#ifdef DEBUG
        printf("aveserver response: %s\n", buff);
#endif
	if (strlen(buff) < 5)
	    continue;
	    
	ptr = buff + 3;
	*ptr = '\0';
	ptr++;
	av_code = atoi(buff);
	
	switch (av_code) {
	    case 200: /* ok|bye */
		goto the_end;
		break;
	    case 201: /* <connection id> counter <unknown> ddmmyyyy <num records> <version> */
	    case 310: /* receiving %d bytes (when NETSCAN) */
	    case 311: /* received %d bytes */
	    case 321: /* currently processed object) */
	    case 325: /* archiver name */
	    case 326: /* (executable packer name) */
		break;    
	    /* virus name */
	    case 322:
		if ((ptr1 = strchr(ptr, ' '))) {
		    *ptr1 = '\0';
		    vir = ptr;
		    /* infected file */
		    ptr = ptr1 + 1;
		    if ((ptr1 = strrchr(ptr, '/'))) {
			*ptr1 = '\0';
			ptr = ptr1 + 1;
			/* remove '\n' and '\r' */
			if ((ptr1 = strchr(ptr, '\r')) 
			    || (ptr1 = strchr(ptr, '\n')))
			    *ptr1 = '\0';
		    }	
		    if (vir && ptr) {
		    	/* add a new line to the AV message */        
        		create_av_message(mess, ptr, vir, "infected:");
		    }
		}    
		break;		
	    case 221: /* file was infected and has been cured */
	    case 230: /* file is infected */
	    case 231: /* file is infected and cannot be cured */
	    case 232: /* file is suspicious */
	    case 233: /* file has warnings */
		response = 1;	    

	    case 220: /* file is clean */
	    case 234: /* file is corrupted */
	    case 240: /* file is encrypted */
	    case 241: /* scan error has been detected */
	    case 401: /* process limit exceeded */
	    case 402: /* couldn't accept client connection */
	    case 500: /* not implemented */
	    case 501: /* unexpected error */
	    case 520: /* path is relative */
	    case 521: /* read access is denied */	
	    case 523: /* directory excluded */
	    case 524: /* directory not included */
	    case 525: /* file not found */	
	    case 526: /* not a file */
	    case 527: /* no required parameters specified */
	    case 528: /* ambigigous option */
	    case 529: /* filename is empty */
	    case 530: /* invalid connection type */
	    case 531: /* bad md5 signature format */
	    case 532: /* incorrect file size */
	    case 533: /* could not receive the file */
	    case 534: /* scan aborted , md5 validation failed */
	    case 535: /* could not send cured file */
		/* close the session */
		if (write(mess->fd, "QUIT\r\n", 7) != 7)
		    return -1;	/* error writing to the aveserver socket */
		break;		
	    default:
		break;	
	}	
    }


the_end:  if (mess->fd != -1)
	    av_disconnect(mess->fd);

    /* store the virus to quarantine for investigation */		
    if (response)
	copy_infected(mess, filename, vir);

    return response;
}


