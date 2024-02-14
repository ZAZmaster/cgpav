/* $Id: email.c, v 1.5 2010/07/01 12:00:00 farit Exp $ */

#include "email.h"

#define INPUT_BUFSIZE 1024
/* maximum number of message lines from the original message */
#define MAX_HEADERLINES 20


/* get e-mail address from the line */
char *parse_email(char *header_line)
{
    char *p_start = NULL;
    char *p_end = NULL;

    p_end = strrchr(header_line, '>');
    if (p_end)
	p_start = strrchr(header_line, '<');

    if (!p_end || !p_start || (p_start >= p_end))
	return NULL;
    else {
	*p_end = '\0';
	p_start++;
    }

    /* simple check for @ sign inside the e-mail */
    if (!(strchr(p_start, '@')))
	return NULL;

    return p_start;
}

/* extract domain from the e-mail */
char *extract_domain(char *email)
{
    char *ptr = NULL;
    
    if (!email)
	return NULL;

    if (!(ptr = strrchr(email, '@'))) 
        return NULL;	
    ptr++;    
	
    return ptr;	    
}


/* get SMTP address from the header line */
unsigned long parse_smtp(char *header_line)
{
    char *p_start = NULL;
    char *p_end = NULL;
    in_addr_t smtp_address;

    p_end = strrchr(header_line, ']');
    if (p_end)
	p_start = strrchr(header_line, '[');

    if (!p_end || !p_start || (p_start >= p_end))
	return -1;
    else {
	*p_end = '\0';
	p_start++;
    }

    /* convert the address into long int (native byte order) */
    /* that's easy to compare */
    smtp_address = inet_addr(p_start);
    if (smtp_address != -1)
	return ntohl(smtp_address);
    else
	return -1;	
}

/* parse the message headers to get sender's and recipients' e-mails */
int parse_headers(MESSAGE *mess)
{
    FILE *message_file;
    char buf[INPUT_BUFSIZE];
    char *ptr = NULL;
    char *domain = NULL;
    in_addr_t smtp_address;
    int i = 0;

    if (!mess)
	return -1;    

    mess->sender = NULL;
    mess->smtp = 0;
    mess->is_sender_local = 0;
    
    /* there can be many recipients , so we use a vector */
    mess->recipients = (char_vector *)malloc(sizeof(char_vector));
    if (!mess->recipients)
        return -1;
    mess->recipients->val = NULL;
    mess->recipients->size = 0;
    mess->recipient_names = NULL;

    /* vector for domains */
    mess->domains = (char_vector *)malloc(sizeof(char_vector));
    if (!mess->domains)
        return -1;
    mess->domains->val = NULL;
    mess->domains->size = 0;
    

    if ((message_file = fopen(mess->filename, "r")) == NULL)
	return -1;

/* the header of the message file, P - sender, R - recipient, S - SMTP server
P I 17-09-2001 09:52:33 0000 ____ ____ <ann@domain.ru>
O T
S SMTP [199.199.199.199]
R W 17-09-2001 09:52:33 0000 ____ _FY_ <nif@guga.ru>
R W 17-09-2001 09:52:33 0000 ____ _FY_ <naf@buki.ru>

*/

    while (fgets(buf, INPUT_BUFSIZE, message_file) != NULL) {
	/* there is an empty line after the header */
	if (strlen(buf) <= 1)
	    break;
	/* if sender */
	if (buf[0] == 'P') {
	    if ((ptr = parse_email(buf))) {
		mess->sender = strdup(ptr);
		if (!mess->sender)
		    return -1;
		/* mess->domains->val[0] - sender */
		if ((domain = extract_domain(ptr))) {
		    if (push_back_vector(mess->domains, domain))
			return -1;
		}	    
	    }
	}
	/* if recipient */
	if (buf[0] == 'R') {
	    if ((ptr = parse_email(buf)))
		if (push_back_vector(mess->recipients, ptr))
		    return -1;
		/* mess->domains->val[1] ... - recipients */
		if ((domain = extract_domain(ptr))) {
		    if (push_back_vector(mess->domains, domain))
			return -1;
		}	    
	}
	/* if SMTP server address */
	if (strncasecmp(buf, "S SMTP", 6) == 0) {
	    if ((smtp_address = parse_smtp(buf)) > 0)
		mess->smtp = smtp_address;
	}
    }
    
    fclose(message_file);

    /* if the virus sender is from one of the local networks */
    if (mess->smtp && sett->local_networks && (sett->local_networks->size > 0)) {
	for (i = 0; i < sett->local_networks->size; i++) {
	    if ((sett->local_networks->val[i]->from <= mess->smtp) 
		&& (mess->smtp <= sett->local_networks->val[i]->to)) {
		mess->is_sender_local = 1;
		break;
	    }    
	}
    }	

    /* check if the sender was from our domain */
    if (sett->local_domains && (sett->local_domains->size > 0) && mess->is_sender_local
	/* domains->val[0] - sender's domain */
	&& (mess->domains->size > 0) && mess->domains->val[0]) { 
	mess->is_sender_local = 0;
	for (i = 0; i < sett->local_domains->size; i++) {
	    if (strcasecmp(sett->local_domains->val[i], 
		mess->domains->val[0]) == 0) {
		mess->is_sender_local = 1;
		break;
	    }
	}    
    }

#ifdef DEBUG
    /* print now what we got */
    print_headers(mess);
#endif

    return 0;
}

#ifdef DEBUG

/* print what we have been able to extract from the headers */
void print_headers(MESSAGE *mess)
{
    int i;

    if (mess->sender)
	printf("Message sender: %s\n", mess->sender);
    
    if (mess->recipients && (mess->recipients->size > 0)) {
	printf("Recipients: ");
	for (i = 0; i < mess->recipients->size; i++)
    	    printf("%s ", mess->recipients->val[i]);
	printf("\n");    
    }

    if (mess->domains && (mess->domains->size > 0)) {
	printf("Domains: ");
	for (i = 0; i < mess->domains->size; i++)
    	    printf("%s ", mess->domains->val[i]);
	printf("\n");    
    }

    if (sett->virtual_domains->size > 0) {
	printf("Notifications for virtual domains: ");
	for (i = 0; i < sett->virtual_domains->size; i++)
	    printf(" %s", sett->virtual_domains->val[i]);
	    
	printf("\n");
    }	    

    if (mess->smtp)
	printf("SMTP address: %s\n", my_ntoa(mess->smtp));

    if (sett->local_networks->size > 0) {
	printf("Local networks: ");
	for (i = 0; i < sett->local_networks->size; i++) {
	    printf(" %s-", my_ntoa(sett->local_networks->val[i]->from));
	    printf("%s ", my_ntoa(sett->local_networks->val[i]->to));
	}    
	printf("\n");
    }	    	
    
    if (sett->local_domains->size > 0) {
	printf("Local domains: ");
	for (i = 0; i < sett->local_domains->size; i++)
	    printf(" %s ", sett->local_domains->val[i]);
	        
	printf("\n");
    }	    	
	

    if (mess->is_sender_local)
	printf("Message sender is local\n");
    else
	printf("Message sender isn't local\n");	

    if (sett->fake_virus_strings->size > 0) {
	printf("Do not send notifications for viruses: ");
	for (i = 0; i < sett->fake_virus_strings->size; i++)
	    printf(" %s", sett->fake_virus_strings->val[i]);
	    
	printf("\n");
    }	    

    if (sett->domain_aliases->size > 0) {
	printf("Domain aliases: ");
	for (i = 0; i < sett->domain_aliases->size; i++)
	    printf(" %s=>%s", sett->domain_aliases->val[i]->name, 
		   sett->domain_aliases->val[i]->val);
	printf("\n");
    }	    


    /* restrictions were enabled */
    if (sett->restrictions == 1) {
	if (sett->scan_domains->size > 0) {
	    printf("Domains to scan: ");
	    for (i = 0; i < sett->scan_domains->size; i++)
		printf(" %s", sett->scan_domains->val[i]);
	    
	    printf("\n");
	}    
    }	    
    else if (sett->restrictions == 2) {
	if (sett->not_scan_domains->size > 0) {
	    printf("Domains not to scan: ");
	    for (i = 0; i < sett->not_scan_domains->size; i++)
		printf(" %s", sett->not_scan_domains->val[i]);
	    
	    printf("\n");
	}    
    }	    

		  
}
#endif

/* free memory allocated in the parse_header function */
void free_headers(MESSAGE *mess)
{
    if (mess->sender) {
	free(mess->sender);
	mess->sender = NULL;
    }	
    if (mess->recipients)
	free_vector(mess->recipients);		    
    if (mess->domains)
	free_vector(mess->domains);	
	
}

static void print_from_host(unsigned long ip, FILE *outfile)
{
    struct in_addr in;
    struct hostent *hp;
    
    if (!ip)
	return;    

    in.s_addr = htonl(ip);
    
    fputs("Message received from: ", outfile);
    if ((hp = gethostbyaddr((char *)&in.s_addr, sizeof(in.s_addr), AF_INET)))
	fprintf(outfile, "%s (%s)", hp->h_name, inet_ntoa(in));
    else
	fprintf(outfile, "%s", inet_ntoa(in));

    fputs("\n", outfile);
    
}

static void print_original_headers(MESSAGE *mess, FILE *outfile)
{
    FILE *msgfile;
    char buf[INPUT_BUFSIZE];
    char *ptr = NULL;
    char *r = NULL;
    int header_lines = MAX_HEADERLINES;
    
    if (!mess || !outfile || !sett->original_message_headers)
	return;
    
    msgfile = fopen(mess->filename, "r");
    if (!msgfile)
	return;
     
    fputs("Original message headers:\n"
	  "============================================================\n\n", 
	  outfile); 

    /* skip the cgpro headers */
    while (!feof(msgfile)) {
	r = fgets(buf, INPUT_BUFSIZE, msgfile);
		 
	if (strlen(buf) < 4) 
	    break;     	   
    }
    
    /* read-write the mail headers */	     
    while (!feof(msgfile) && header_lines) {
	r = fgets(buf, INPUT_BUFSIZE, msgfile);
	header_lines--;
    
	ptr = buf + strlen(buf) - 1;
	/* skip win CR '\r\n' */
	if ((*ptr == '\n') || (*ptr == '\r'))
	    *ptr = '\0';
	ptr--;
	if ((*ptr == '\n') || (*ptr == '\r'))
	    *ptr = '\0';    
    
	/* there is an empty line after the headers */
	if (strlen(buf) < 1)
	    break;
	fprintf(outfile, "%s\n", buf);
    }
    
    fclose(msgfile);
    fputs("\n============================================================\n\n", 
	  outfile);
    	    
}

/* send notificaton to postmaster */
int create_message_postmaster(MESSAGE *mess, char *domain, char *to_from, 
	int random_val)
{
    char *postmaster_email = NULL;
    
    if (!mess || !domain)
	return -1;

    /* construct postmaster's e-mail */
    postmaster_email = (char *)malloc(strlen(sett->virtual_postmaster_account) 
				      + 1 + strlen(domain) + 1);
    if (!postmaster_email) 
	return -1;    
                    
    sprintf(postmaster_email, "%s@%s", sett->virtual_postmaster_account, 
	    domain);
    postmaster_notification(mess, postmaster_email, to_from, random_val);
	
    if (postmaster_email)
	free(postmaster_email);                        
    
    return 0;	
}

/* send notifications for postmasters of virtual domains */
int send_virtual_postmasters(MESSAGE *mess)
{
    int i = 0, j = 0;

    if (!sett->virtual_postmaster_notification || !mess)	
	return -1;
    	
    /* all (From and To) notifications */
    if ((sett->virtual_postmaster_notification == 1)
	/* virus sent From the postmaster's domain */ 
	|| (sett->virtual_postmaster_notification == 2)) {
	/* go through virtual domains */
	for (i = 0; i < sett->virtual_domains->size; i++) {
	    /* mess->domains->val[0] is sender's domain */
	    if (strcasecmp(sett->virtual_domains->val[i], 
		mess->domains->val[0]) == 0)
	    /* i + 1 - to create random number as 0 - notification to
		postmaster of the whole mail server */	
		create_message_postmaster(mess, mess->domains->val[0], 
					  "from your user ", i + 1); 
	}	
    }

    /* if all */    
    if ((sett->virtual_postmaster_notification == 1)
	/* sent To the postmaster's domain */ 
	|| (sett->virtual_postmaster_notification == 3)) {
	/* go through recipients' domains first */
	/* their index begins from 1 */
	for (j = 1; j < mess->domains->size; j++) {
	    /* then through virtual domains */
	    for (i = 0; i < sett->virtual_domains->size; i++) {
		if (strcasecmp(sett->virtual_domains->val[i],
			       mess->domains->val[j]) == 0)  	
		create_message_postmaster(mess, mess->domains->val[j], 
					  "to your user ", 
			/* trying to make the notification name unique */
			1000 + i + (mess->domains->size - 1) * j); 
	    }	
	}
    }
    
    return 0;
}

/* rename a file with .tmp extension to the file with .sub */
/* first we write to file .tmp then quickly rename it to .sub */ 
static int tmp_to_sub(char *filename)
{
    char *file_original = NULL;
    int len = 0;
    
    if (!filename)
	return -1;
    
    /* new file with the .sub extension */
    if (!(file_original = strdup(filename)))
	return -1;
	
    len = strlen(filename); 

    filename[len - 3] = 's';
    filename[len - 2] = 'u';
    filename[len - 1] = 'b';    

    rename(file_original, filename);
    
    if (file_original)
	free(file_original);
    
    return 0;
}


int sender_notification(MESSAGE *mess)
{
    FILE *outfile;
    char *outfile_name = NULL;

    outfile_name =
	(char *)malloc(strlen(sett->cgpro_submitted) + 1 
			+ strlen(mess->seqnum) + 7 + 1);
    if (outfile_name == NULL)
	return -1;

    sprintf(outfile_name, "%s/%svir.tmp", sett->cgpro_submitted, 
	    mess->seqnum);

    if (!(outfile = fopen(outfile_name, "w"))) {
	if (outfile_name)
	    free(outfile_name);
	return -1;
    }

    /* text of the message of the virus notification to the virus sender */
    fprintf(outfile,
	    "From: \"Antivirus\" <%s>\n"
	    "To: <%s>\n"
	    "Subject: %s\n"
	    "MIME-Version: 1.0\n"
	    "Content-Type: text/plain;charset=%s\n"
	    "Content-Transfer-Encoding: 8bit\n"
	    "X-Priority: 1\n"
	    "X-MSMail-Priority: High\n\n"
	    "Attention! You sent an infected message with the\n",
	    sett->antivirus_email, 
	    mess->sender, 
	    sett->sender_subject,
            sett->charset);

    fprintf(outfile, 
	    (mess->viruses->size > 1) ? "VIRUSES: %s\n" : "VIRUS: %s\n",
	    mess->virus_names);
    fprintf(outfile, "TO: %s\nIt was rejected for delivery.\n\n", 
	    mess->recipient_names);

    /* Russian text */
    if (sett->russian) {
	fprintf(outfile, "÷ÎÉÍÁÎÉÅ! ÷Ù ÐÏÓÌÁÌÉ ÓÏÏÂÝÅÎÉÅ Ó\n");
	fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷éòõóáíé: %s\n" : "÷éòõóïí: %s\n",
		mess->virus_names);
	fprintf(outfile, "äìñ: %s\nïÎÏ ÂÙÌÏ ÏÔ×ÅÒÇÎÕÔÏ ÄÌÑ ÄÏÓÔÁ×ËÉ.\n\n",
		mess->recipient_names);
    }

    /* German text */
    if (sett->german) {
	fprintf(outfile,
		"Achtung! Sie haben eine Nachricht mit einem Virus versendet.\n");
	fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRUS: %s\n" : "VIRUS: %s\n",
		mess->virus_names);
	fprintf(outfile,
		"AN: %s\nDie Nachricht wurde nicht ausgeliefert.\n\n",
		mess->recipient_names);
    }

    /* Italian text */
    if (sett->italian) {
	fprintf(outfile, "Attenzione! Hai spedito un messaggio con il\n");
	fprintf(outfile, "VIRUS: %s\n", mess->virus_names);
	fprintf(outfile, "A: %s\nE' stato rifiutata la consegna.\n\n",
		mess->recipient_names);
    }

    /* French text */
    if (sett->french) {
	fprintf(outfile, "Attention! Vous avez envoyé votre message avec\n");
	fprintf(outfile, "VIRUS: %s\n", mess->virus_names);
	fprintf(outfile, "POUR: %s\nLe message a été refusé.\n\n",
		mess->recipient_names);
    }

    /* Spanish text */
    if (sett->spanish) {
	fprintf(outfile, "Atencién! Usted ha mandado un messaje con el\n");
	fprintf(outfile, "VIRUS: %s\n", mess->virus_names);
	fprintf(outfile, "A: %s\nFue rechazado para la salida.\n\n",
		mess->recipient_names);
    }

    /* Tatar text */
    if (sett->tatar) {
	fprintf(outfile, "éÓËÁ ÁÌÙÇÙÚ! óÅÚ");
	fprintf(outfile, " %s ÖÉÂÁÒÇÁÎ ÈÁÂÁÒÇÁ\n", mess->recipient_names);
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷éòõóìáò: %s " : "÷éòõó: %s",
                mess->virus_names);        
	fprintf(outfile, " ËÙÓÔÙÒÙÌÇÁÎ.\nõÌ ÈÁÂÁÒ ÔÁÐÛÙÒÙÌÍÁÄÙ.\n\n");
    }

    /* Latvian text */
    if (sett->latvian) {
	fprintf(outfile, "Uzmanibu! Jums nosutija vestuli ar\n");
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRUSIEM: %s\n" : "VIRUSU: %s\n",
                mess->virus_names);        
	fprintf(outfile, "KAM: %s\nSi vestule netika nogadata.\n\n",
		mess->recipient_names);
    }

    /* Ukrainian text */
    if (sett->ukrainian) {
	fprintf(outfile, "õ×ÁÇÁ! ÷É ÎÁÄiÓÌÁÌÉ Ú×iÓÔËÕ Ú\n");
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷Iòõóïí: %s\n" : "÷Iòõóáíé: %s\n",
                mess->virus_names);        
	fprintf(outfile, "äìñ: %s\n÷ÏÎÏ ÎÅ ÂÕÌÏ ÐÒÉÊÎÑÔÏ ÄÌÑ ÄÏÓÔÁ×ËÉ.\n\n",
		mess->recipient_names);
    }

    /* Dutch text (by Eric Limpens) */
    if (sett->dutch) {
	fprintf(outfile, 
	    "Attentie! U heeft een virus besmet bericht verzonden.\n");
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRI: %s\n" : "VIRUS: %s\n",
                mess->virus_names);        
	fprintf(outfile, "Aan: %s\nHet bericht is geweigerd.\n\n",
		mess->recipient_names);
    }
    
    /* Additional text */
    if (sett->own_text)
	fprintf(outfile, "%s\n", sett->own_text);

    print_from_host(mess->smtp, outfile);
    print_original_headers(mess, outfile);

    fclose(outfile);

    tmp_to_sub(outfile_name);

#ifdef DEBUG
    printf("Sender %s notification %s\n", 
	    mess->sender, outfile_name);
#endif

    if (outfile_name)
	free(outfile_name);
	
    return 0;
}


int recipient_notification(MESSAGE *mess, char *recipient, int random_val)
{
    FILE *outfile;
    char *outfile_name = NULL;

    if (!mess || !recipient)
	return -1;

    outfile_name = (char *)malloc(strlen(sett->cgpro_submitted) + 1
				  + strlen(mess->seqnum)
				  + sizeof(int) + 7 + 1);
    if (outfile_name == NULL)
	return -1;

    sprintf(outfile_name, "%s/%s%dvir.tmp", sett->cgpro_submitted, 
	    mess->seqnum, random_val);

    if ((outfile = fopen(outfile_name, "w")) == NULL) {
	if (outfile_name)
	    free(outfile_name);
	return -1;
    }

    /* text of the message notification to the virus recipient */
    fprintf(outfile,
	    "From: \"Antivirus\" <%s>\n"
	    "To: <%s>\n"
	    "Subject: %s\n"
	    "MIME-Version: 1.0\n"
	    "Content-Type: text/plain;charset=%s\n"
	    "Content-Transfer-Encoding: 8bit\n"
	    "X-Priority: 1\n"
	    "X-MSMail-Priority: High\n\n",
	    sett->antivirus_email, 
	    recipient, 
	    sett->recipient_subject,
            sett->charset);

    /* English text, always */
    fprintf(outfile, "Attention! We received a message for you with\n");
    fprintf(outfile, 
	    (mess->viruses->size > 1) ? "VIRUSES: %s\n" : "VIRUS: %s\n",
	    mess->virus_names);
    fprintf(outfile, "The sender's address is %s, but it's probably forged.\n",
	    mess->sender);
    fprintf(outfile, "The message was rejected for delivery.\n\n");

    /* Russian text */
    if (sett->russian) {
	fprintf(outfile, "÷ÎÉÍÁÎÉÅ! íÙ ÐÏÌÕÞÉÌÉ ÓÏÏÂÝÅÎÉÅ ÄÌÑ ×ÁÓ Ó\n");
	fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷éòõóáíé: %s\n" : "÷éòõóïí: %s\n",
		mess->virus_names);
	fprintf(outfile, "áÄÒÅÓ ÏÔÐÒÁ×ÉÔÅÌÑ %s, ÎÏ ÏÎ ÍÏÖÅÔ ÂÙÔØ ÐÏÄÄÅÌÁÎ.\n",
		mess->sender);

	fprintf(outfile, "óÏÏÂÝÅÎÉÅ ÂÙÌÏ ÏÔ×ÅÒÇÎÕÔÏ ÄÌÑ ÄÏÓÔÁ×ËÉ.\n\n");
    }

    /* German text */
    if (sett->german) {

	fprintf(outfile, "Achtung! Wir haben eine an Sie gerichtete Virus-Email erhalten.\n"
		"Die Absenderadresse lautet %s, ist aber wahrscheinlich gefälscht.\n",
 		mess->sender);
	fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRUS: %s\n" : "VIRUS: %s\n",
		mess->virus_names);
	fprintf(outfile, "Die Nachricht wurde nicht ausgeliefert.\n\n");
    }

    /* Italian text */
    if (sett->italian) {
	fprintf(outfile, "Attenzione! %s ti ha spedito un messaggio con il\n",
		mess->sender);
	fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRUS: %s\n" : "VIRUS: %s\n",
		mess->virus_names);
	fprintf(outfile, "Non ti è stato consegnato.\n\n");
    }

    /* French text */
    if (sett->french) {
	fprintf(outfile, "Attention! On vous a envoyé un message avec un virus.\n"
		"L'adresse d'expéditeur est %s mais peut être faux.\n",
 		mess->sender);
	fprintf(outfile, "VIRUS: %s\n", mess->virus_names);
	fprintf(outfile, "Le message a été refusé.\n\n");
    }

    /* Spanish text */
    if (sett->spanish) {
	fprintf(outfile, "Atencién! %s le mandé un message con el\n",
		mess->sender);
	fprintf(outfile, "VIRUS: %s\n", mess->virus_names);
	fprintf(outfile, "No le fue entregado.\n\n");
    }

    /* Tatar text */
    if (sett->tatar) {
	fprintf(outfile, "éÓËÁ ÁÌÙÇÙÚ! %s ÓÅÚÇÁ\n", mess->sender);
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷éòõóìáò: %s\n" : "÷éòõó: %s\n",
                mess->virus_names);
	fprintf(outfile, "ËÙÓÔÙÒÙÌÇÁÎ ÈÁÂÁÒ ÖÉÂÁÒÇÁÎ.\n");
        fprintf(outfile, "õÌ ÓÅÚÇÁ ÔÁÐÛÙÒÙÌÍÁÄÙ.\n\n");
    }

    /* Latvian text */
    if (sett->latvian) {
	fprintf(outfile, "Uzmanibu! %s nosutija Jums vestuli ar\n", 
                mess->sender);
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRUSIEM: %s\n" : "VIRUSU: %s\n",
                mess->virus_names);
        fprintf(outfile, "Si vestule netika nogadata.\n\n");
    }

    /* Ukrainian text */
    if (sett->ukrainian) {
	fprintf(outfile, "õ×ÁÇÁ! %s ÐÏÓÌÁ× ×ÁÍ Ú×iÓÔËÕ Ú\n", 
                mess->sender);
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "÷Iòõóïí: %s\n" : "÷Iòõóáíé: %s\n",
                mess->virus_names);
        fprintf(outfile, "÷ÏÎÏ ÎÅ ÂÕÌÏ ÐÒÉÊÎÑÔÏ ÄÌÑ ÄÏÓÔÁ×ËÉ.\n\n");
    }

    /* Dutch text */
    if (sett->dutch) {
	fprintf(outfile, "Attentie! %s stuurde u een besmet email bericht\n", 
                mess->sender);
        fprintf(outfile, 
		(mess->viruses->size > 1) ? "VIRI: %s\n" : "VIRUS: %s\n",
                mess->virus_names);
        fprintf(outfile, "Het bericht is geweigerd.\n\n");
    }

    /* Additional text */
    if (sett->own_text)
	fprintf(outfile, "%s\n", sett->own_text);

    /* print the host the message was sent from */
    print_from_host(mess->smtp, outfile);

    /* print mail headers of the original message */
    print_original_headers(mess, outfile);


    fclose(outfile);

    tmp_to_sub(outfile_name);
    
#ifdef DEBUG
    printf("Recipient %s notification %s\n", 
	    recipient, outfile_name);
#endif

    if (outfile_name)
	free(outfile_name);
	
    return 0;
}

/* send a notification to postmaster */
int postmaster_notification(MESSAGE *mess, char *postmaster_email, 
			    char *to_from, int random_val)
{
    FILE *outfile;
    char *outfile_name = NULL;

    if (!mess || !postmaster_email)
	return -1;

    
    outfile_name = (char *)malloc(strlen(sett->cgpro_submitted) + 1 
                                  + strlen(mess->seqnum) + 1 + sizeof(int) 
				  + 7 + 1);
    if (outfile_name == NULL)
	return -1;

    sprintf(outfile_name, "%s/%sp%dvir.tmp", sett->cgpro_submitted, 
	    mess->seqnum, random_val);

    if (!(outfile = fopen(outfile_name, "w"))) {
	if (outfile_name)
	    free(outfile_name);
	return -1;
    }

    /* text of the message of the virus notification to postmaster */
    fprintf(outfile,
	    "From: \"Antivirus\" <%s>\n"
	    "To: <%s>\n"
	    "Subject: VIRUS %s your user\n"
	    "MIME-Version: 1.0\n"
	    "Content-Type: text/plain;charset=%s\n"
	    "Content-Transfer-Encoding: 8bit\n"
	    "X-Priority: 1\n"
	    "X-MSMail-Priority: High\n\n"
	    "Attention! The message was sent %swith\n",
	    sett->antivirus_email, postmaster_email, to_from, sett->charset,
	    to_from
	    );

    fprintf(outfile, 
	    (mess->viruses->size > 1) ? "VIRUSES: %s\n" : "VIRUS: %s\n",
	    mess->virus_names);
    fprintf(outfile, "FROM: %s\n", 
            mess->sender);            
    fprintf(outfile, "TO: %s\nIt was rejected for delivery.\n\n", 
	    mess->recipient_names);

    /* print the host the message was sent from */
    print_from_host(mess->smtp, outfile);

    /* print mail headers of the original message */
    print_original_headers(mess, outfile);

    fclose(outfile);

    tmp_to_sub(outfile_name);

#ifdef DEBUG
    printf("Postmaster %s notification %s\n", 
	    postmaster_email, outfile_name);
#endif

    if (outfile_name)
	free(outfile_name);
        
    return 0;
}


/* construct and send all notifications */
int email_notifications(MESSAGE *mess)
{
    int i = 0;

    if (!mess)
	return -1;
	

    if (mess->sender && mess->recipient_names && mess->virus_names
	&& (mess->domains->size > 0)) {
					
	/* send notification to the virus sender */
	if (sett->sender_notification
	    /* sender is local */
	    || (mess->is_sender_local 
		/* notification to sender and recipients */
		&& ((sett->local_notification == 1) 
		    /* notification to sender */
		    || (sett->local_notification == 2)))) {
	    sender_notification(mess);
	}    
	    
	/* send notification to virus recipients */
	if (sett->recipients_notification
	    /* sender is local */
	    || (mess->is_sender_local 
		/* notification to sender and recipients */
		&& ((sett->local_notification == 1) 
		    /* notification to recipients */
		    || (sett->local_notification == 3)))) {
	    for (i = 0; i < mess->recipients->size; i++)
		recipient_notification(mess, mess->recipients->val[i], i);
        }

	if (sett->postmaster_notification)
	    postmaster_notification(mess, sett->postmaster_account, "", 0);    	
	
	if (sett->virtual_postmaster_notification)
	    send_virtual_postmasters(mess);
		
    }
    else 
	return -1;

    return 0;
}
