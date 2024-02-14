/* $Id: drwebcomm.c, v 1.3 2003/10/17 12:00:00 farit Exp $ */

#include "drwebcomm.h"

/* Dr.Web commands */
#define DRWEBD_SCAN_CMD       0x0001

/* Dr.Web SCAN_CMD flags */
#define DRWEBD_RETURN_VIRUSES 0x0001
#define DRWEBD_HEURISTIC_ON   0x0008

#define DRWEBD_SCAN_FLAGS (DRWEBD_RETURN_VIRUSES/*|DRWEBD_HEURISTIC_ON*/)

/* Dr.Web result codes */
#define DERR_READ_ERR		0x00001
#define DERR_WRITE_ERR		0x00002
#define DERR_NOMEMORY		0x00004
#define DERR_CRC_ERROR		0x00008
#define DERR_READSOCKET		0x00010
#define DERR_KNOWN_VIRUS	0x00020
#define DERR_UNKNOWN_VIRUS	0x00040
#define DERR_VIRUS_MODIFICATION	0x00080
#define DERR_TIMEOUT		0x00200
#define DERR_SYMLINK		0x00400
#define DERR_NO_REGFILE		0x00800
#define DERR_SKIPPED		0x01000
#define DERR_TOO_BIG		0x02000
#define DERR_TOO_COMPRESSED	0x04000
#define DERR_BAD_CALL		0x08000
#define DERR_EVAL_VERSION	0x10000
#define DERR_SPAM_MESSAGE	0x20000

#define DERR_VIRUS \
  (DERR_KNOWN_VIRUS|DERR_UNKNOWN_VIRUS|DERR_VIRUS_MODIFICATION)



/* check each part of the mail message */
/* returns 0 - clean, 1 - infected */
int is_infected(MESSAGE *mess, char *original_filename, char *filename) 
{
    int response = 0;
    char buff[1024];
    int c, len;
    char *ptr = NULL;    
    int code = 0;
    int vir_num = 0;
    char *vir = NULL;

    
    if (!mess && !filename)
	return 0;
    
    /* connect to the drwebd socket */
    if (!sett->drwebd_socket)
	return -1;		/* can't connect to the drwebd socket */

    if ((mess->fd = connect_socket(sett->drwebd_socket)) == -1) {
#ifdef DEBUG
	printf("ERROR! Can't connect to the drwebd daemon socket: %s\n"
		"Check drwebd_socket option in the cgpav.conf\n", 
		sett->drwebd_socket);	    
#endif
	return -1;	/* error connecting to the clamd socket */
    }


    ptr = buff;
    c = htonl(DRWEBD_SCAN_CMD); 
    memcpy(ptr, &c, sizeof(int)); 
    ptr += sizeof(int);
    
    c = htonl(DRWEBD_SCAN_FLAGS); 
    memcpy(ptr, &c, sizeof(int)); 
    ptr += sizeof(int);
    
    len = strlen(filename);
    c = htonl(len); 
    memcpy(ptr, &c, sizeof(int)); 
    ptr += sizeof(int);
    
    memcpy(ptr, filename, len); 
    ptr += len;
    
    c = htonl(0); 
    memcpy(ptr, &c, sizeof(int)); 
    ptr += sizeof(int);
    
    len = ptr - buff;
    
    if (write(mess->fd, buff, len) != len) 
	return -1;	/* error writing to the drwebd socket */

    /* return code */
    if (timeout_read(sett->av_timeout, mess->fd, 
	(char *)&code, sizeof(int)) != sizeof(int))
	return -2;	/* unable to read drwebd response, timeout */

    /* number of viruses */
    if (timeout_read(sett->av_timeout, mess->fd, 
	(char *)&vir_num, sizeof(int)) != sizeof(int))
	return -2;	/* unable to read drwebd response, timeout */

    code = ntohl(code);
    vir_num = ntohl(vir_num);
            
#ifdef DEBUG
    printf("Scan result. Code: %d (0x%x), Number of viruses: %d\n", 
	    code, code, vir_num);
#endif
    
    /* no virus found */
    if (code == 0) 
	response = 0;
    /* virus found */	
    else if (vir_num && (code & DERR_VIRUS)) {	    	
	response = 1;
	for (; vir_num > 0; vir_num--) {	
	    /* virus name length */
	    if (timeout_read(sett->av_timeout, mess->fd, 
		(char *)&len, sizeof(int)) != sizeof(int))
		return -2;	/* unable to read drwebd response, timeout */
	    
	    len = ntohl(len);
	    /* though length of the buff must be enough for virus names */
	    if (len > sizeof(buff))
		len = sizeof(buff);
	
	    if (timeout_read(sett->av_timeout, mess->fd, buff, len) != len) 
		return -2;	/* unable to read drwebd response, timeout */

	    vir = buff;
	    /* remove unnecessary information */
	    clear_string("infected with ", &vir);
	    				    
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



