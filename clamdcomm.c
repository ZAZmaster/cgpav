/* $Id: clamdcomm.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "clamdcomm.h"


/* check each part of the mail message */
/* returns 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename) 
{
    char *request = NULL;
    int response = 0;
    char buff[1024];   
    char *vir = NULL, *p1 = NULL;

    memset(buff, 0, sizeof(buff));


    /* connect to clamd */
    if (!sett->clamd_socket)
	return -1;		/* can't connect to the clamd socket */

    if ((mess->fd = connect_socket(sett->clamd_socket)) == -1) {
#ifdef DEBUG
    printf("ERROR! Can't connect to the clamd daemon socket: %s\n"
	   "Check clamd_socket in cgpav.conf\n", 
	    sett->clamd_socket);	    
#endif
	return -1;	/* error connecting to the clamd socket */
    }

    /* prepare clamd command */
    if (!(request = (char *)malloc(strlen("CONTSCAN") + 1 + strlen(filename) 
	  + 1)))
	return -1;	/* error allocating memory */

    sprintf(request, "CONTSCAN %s", filename);
    if (write(mess->fd, request, strlen(request)) != strlen(request)) {
	if (request)
	    free(request);
	return -1;	/* error writing to the clamd socket */
    }

    if (request)
	free(request);

     while (readline(sett->av_timeout, mess->fd, 
    	    (char *)&buff, sizeof(buff)) > 0) {
            
#ifdef DEBUG
        printf("Clamd scan result: %s\n", buff);
#endif
    	
        /* virus found */	
        if ((p1 = strstr(buff, "FOUND\n"))) {
	    response = 1;
	
	    vir = strchr(buff, ':') + 1;
	    p1--;

	    /* remove trailing and beginning spaces */
	    while ((isspace((int)*p1)) && (p1 >= vir))
	        *p1-- = '\0';
	    while (isspace((int)*vir))
	        vir++;

	    /* add a new line to the AV message */        
            create_av_message(mess, original_filename, vir, "infected:");

	    /* store the virus to quarantine for investigation */		
	    copy_infected(mess, filename, vir);
		
        }
    }

    if (mess->fd != -1)
	av_disconnect(mess->fd);
    
    return response;
}



