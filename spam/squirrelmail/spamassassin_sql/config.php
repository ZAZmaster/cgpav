<?php

// module with CommuniGate Pro interface functions
include_once("CLI.php");
include_once("cache_lite.php");

// Web-interface for SpamAssassin and cgpav
// Configuration file

// DEBUG mode, 1 or 0
$CONF['debug'] = 0;

// CommuniGate Pro server address
$CONF['cgpro_address'] = "localhost";

// CommuniGate Pro PWD(administrative) port. Usually, 106
$CONF['cgpro_port'] = 106; 

// CommuniGate Pro account that has ability to list domains 
// and create rules for users
// In Access Rights -> Can Modify mark 'All domains and Accounts Settings'
 
$CONF['cgpro_admin'] = "spamadmin";
$CONF['cgpro_admin_password'] = "secret";

// Use encrypted passwords(requires CommuniGate Password Encryption A-crpt)
// options: no - 0, yes - 1
$CONF['encrypted_cgpro_password'] = 1;

// Cache options, lifeTime is in secs
$CONF['cacheOptions'] = array(
    'cacheDir'	=> 'cache/',
    'lifeTime'	=> '86400'
);    

// Database connection DSN. The format for it is:
// mysql://user:pass@hostname/dbname 
$CONF['DSN'] = "mysql://spamassassin:secret@localhost/spamassassin";

// Database user score preference table. Usually, userpref
$CONF['userpref_table'] = "userpref";

// Folder to store spam.
// Use the delete_old_mail script in the cron dir to delete
// mail in this folder older than n-days
$CONF['spam_folder'] = "Spam";

// Default action on spam detection
// 0 - none (disable spam scanning)
// 1 - default (admin defined in cgpav.conf)
// 2 - reject (send an Undeliverable report to spam senders)
// 3 - discard (quietly delete a spam message)
// 4 - addheader (add the mail header X-Spam-Status)
// 5 - addheader and rule (add the mail header X-Spam-Status and 
// create CommuniGate Pro rule to store spam in the spam_folder
$CONF['default_spamcgpd_action'] = 1;

// Required hits (spam scores) values list
// comma separated list: "1, 2, 3"
$CONF['required_hits'] = "1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18,  19, 20, 25, 30, 35";

// Default value for required_hits
$CONF['default_required_hits'] = 5;

// colors
// framed text color
$CONF['color'][0] = "#dcdcdc";
// background
$CONF['color'][1] = "white";

// SpamAssassin configuration .cf files dir
// Comma separated list of dirs
// Please, place default dirs first
$CONF['spamassassin_cf_dirs'] = "/usr/share/spamassassin, /usr/local/share/spamassassin, /etc/spamassassin, /etc/mail/spamassassin";

// SpamAssassin score type
// SpamAssassin scores depends on its configuration and connection type.
// Options are: local, net, bayes, bayesnet
$CONF['score_type'] = "bayesnet";

// SpamAssassin tests descriptions language
// You can choose translated descriptions for several languages.
// Options are (check the current version of SA): de, es, fr, it, pl, sk
$CONF['description_language'] = "";


?>