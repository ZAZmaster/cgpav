/* $Id: sophoscomm.c, v 1.3 2003/11/07 12:00:00 farit Exp $ */

#include "sophoscomm.h"


/* check each part of the mail message */
/* returns 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename) 
{
    char *request = NULL;
    int response = 0;
    char buff[1024];   
    char *vir = NULL, *p1 = NULL;

    memset(buff, 0, sizeof(buff));


    /* connect to sophie */
    if (!sett->sophos_socket)
	return -1;		/* can't connect to the sophie socket */

    if ((mess->fd = connect_socket(sett->sophos_socket)) == -1) {
#ifdef DEBUG
	printf("ERROR! Can't connect to the sophie daemon socket: %s\n"
		"Check sophos_socket in cgpav.conf "
		"and its permissions.\n", sett->sophos_socket);
#endif
	return -1;	/* error connecting to the sophie socket */
    }

    /* prepare sophie command */
    if (!(request = (char *)malloc(strlen(filename) + 1 + 1)))
	return -1;	/* error allocating memory */

    sprintf(request, "%s\n", filename);
    if (write(mess->fd, request, strlen(request)) != strlen(request)) {
	if (request)
	    free(request);
	return -1;	/* error writing to the sophie socket */
    }

    if (request)
	free(request);

    if (timeout_read(sett->av_timeout, mess->fd, (char *)&buff, 
        	     sizeof(buff)) <= 0)
        return -2;
                
    if ((p1 = strchr(buff, '\n')))
        *p1 = '\0';

#ifdef DEBUG
    printf("Scan result: %s\n", buff);
#endif
    
    /* virus found */	
    if (buff[0] == '1') {
	response = 1;
	vir = buff + 2;
        
        create_av_message(mess, original_filename, vir, "infected:");
	
	/* store the virus to quarantine dir for investigation */		
	copy_infected(mess, filename, vir);
    }    

    if (mess->fd != -1)
	av_disconnect(mess->fd);
    
    return response;
}


