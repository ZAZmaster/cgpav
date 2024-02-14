<?php 

include_once("config.php");
include_once("DB.php");

    
// list all domains of the CommuniGate Pro server
function list_all_domains($selected_domain)
{
    global $CONF; 
    $html = "";

    // cache domains list for a day    
    $cacheLite = new Cache_Lite($CONF['cacheOptions']);    

    // if the value is cached 
    if ($allDomains = $cacheLite->get('allDomains')) {
	$domains = unserialize($allDomains);	
    }
    else {
	// try to connect
	$cli = new CLI;
	if ($CONF['debug'])	
    	    $cli->setDebug(1);

	$cli->Login($CONF['cgpro_address'], $CONF['cgpro_port'], 
		    $CONF['cgpro_admin'], $CONF['cgpro_admin_password'],
		    $CONF['encrypted_cgpro_password']);
    
	// get list of domains
	$domains = $cli->ListDomains();    
	$cli->Logout();
	
	// save domains list to the cache
	$allDomains = serialize($domains);
	$cacheLite->save($allDomains);	
    }	

    if (!empty($domains)) {    
	$html .= "<select name=\"domain\">\n";
	foreach ($domains as $domain) {
	    $html .= "<option value=\"$domain\"";
	    if ($domain == $selected_domain) 
		$html .= " selected";
	    $html .= ">$domain</option>\n";    
	}
	$html .= "</select>";
    }
    
    return $html;
}

// check user against the CommuniGate Pro server
function authenticate_user($username, $password)
{
    global $CONF;
    
    if (!$username || !$password)
	return -1;
	
    $cli = new CLI;
    if ($CONF['debug'])
	$cli->setDebug(1);
	
    $cli->Login($CONF['cgpro_address'], $CONF['cgpro_port'],
		$username, $password, $CONF['encrypted_cgpro_password']);

    $success = $cli->isSuccess();
    
    // successfully connected
    if ($success) {
	$cli->Logout();
	
	return 0;
    }	
    
    return 1;
}

// connect to the database
function connect_db()
{
    global $CONF;
    
    if (!isset($CONF['DSN']))
	return "";
    
    $dbh = DB::connect($CONF['DSN']);

    if (DB::isError($dbh)) {
	if ($CONF['debug']) 
	    echo("Database error: " . DB::errorMessage($dbh) . "<br>\n");
	
	return "";    
    }
    
    return $dbh;
}

// close connection to the database
function disconnect_db($dbh)
{
    if (!isset($dbh))
	return;

    $dbh->disconnect();	
}

// create the html table with white/black addresses
function show_white_black(&$error_msg, $dbh, $username)
{
    global $CONF;
    $html = '';

    if (!isset($dbh) || !isset($username))
	return;

    $sql = "SELECT prefid, preference, value from ". $CONF['userpref_table']
	    ." WHERE username='$username' AND (preference = 'whitelist_from'"
	    ." OR preference = 'blacklist_from') ORDER BY preference DESC, "
	    ." value ASC ";
    $sth = $dbh->query($sql);
    if (DB::isError($dbh)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));	
	return "";    
    }
    
    while ($row = $sth->fetchRow(DB_FETCHMODE_ASSOC)) {
	$html .= "        <tr bgcolor=\"". $CONF['color'][1] ."\">\n";
	$html .= "          <td>". $row['value'] ."</td>\n";
	$html .= "          <td>". ($row['preference'] == "whitelist_from" 
		    ? "Allow" : "Deny") . "</td>\n";
    	$html .= "          <td><a href='options.php?delete=". $row['prefid'] 
	    ."'>Delete</a>";
	$html .= "&nbsp;<a href='options.php?edit=". $row['prefid'] 
	    ."'>Edit</a></td>\n";
	$html .= "        </tr>\n";    	    
    }
    
    return $html;
}

// add an address to the white or black lists
function add_white_black(&$error_msg, $dbh, $username, $action, $editid, 
    $address, $preference)
{ 
    global $CONF;

    if (!isset($dbh) || !isset($username) || !isset($action))
	return -1;
	
    $address = trim($address);	
	
    if (!isset($address)) {
	array_push($error_msg, "Error: you must enter an address.");
	return -1;
    }
    
    $address = preg_replace("/[\s\"\']/", "", $address);
    
    if (!isset($preference)) {
	array_push($error_msg, "Error: you must select Allow or Deny.");
	return -1;
    }
    
    if (!ereg("^[a-zA-Z0-9_\.\-]+@[\*a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+$", $address) 
	&& !ereg("^[\*a-zA-Z0-9\-]+\.[a-zA-Z0-9\-\.]+$",  $address)) {
	array_push($error_msg, "Error: enter a valid address.");
	return -1;
    }

    if ($action == "new") {
	$sql = "SELECT COUNT(*) FROM ". $CONF['userpref_table'] 
	       ." WHERE username='$username' AND value='$address'";     	 	
	$sth = $dbh->query($sql);
	if (DB::isError($sth)) {
	    if ($CONF['debug']) 
		array_push($error_msg, "Database error: ". 
		    DB::errorMessage($dbh));
	    return -1;
	}
	$row = $sth->fetchRow();	
	if ($row[0] > 0) {
	    array_push($error_msg, "Error: duplicate address");	
	    return -1;
	}
	
	$sql = "INSERT INTO ". $CONF['userpref_table']
	       ." (preference, value, username) VALUES ("
	       ."'$preference', '$address', '$username')";	 

	$sth = $dbh->query($sql);
	if (DB::isError($sth)) {
	    if ($CONF['debug']) 
		array_push($error_msg, "Database error: ". 
		    DB::errorMessage($dbh));
		    
	    return -1;	    
	}	
	
	array_push($error_msg, "The address successfully inserted.");
    }
    else if (($action == "update") && $editid) {
	$sql = "UPDATE ". $CONF['userpref_table']
	       ." SET value='$address', preference='$preference'"
	       ." WHERE prefid='$editid'";
	$sth = $dbh->query($sql);
	if (DB::isError($sth)) {
	    if ($CONF['debug']) 
		array_push($error_msg, "Database error: ". 
		    DB::errorMessage($dbh));
		    
	    return -1;	    
	}	
    }	       

    return 0;    	
}


function get_id(&$error_msg, $dbh, $username, $id,
    &$preference, &$value)
{
    global $CONF;
    
    if (!$username || !$id)
	return -1;
    
    $sql = "SELECT preference, value FROM ". $CONF['userpref_table'] 
	   ." WHERE username='$username' AND prefid='$id'";     	 	
    $sth = $dbh->query($sql);
    if (DB::isError($sth)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));
		
	return -1;
    }
    
    $row = $sth->fetchRow();	
    if (isset($row[0]) && isset($row[1])) {
	$preference = $row[0];
	$value = $row[1];
    }	
    else 
	return -1;
    
    return 0;
}

function delete_id(&$error_msg, $dbh, $username, $id)
{
    global $CONF;
    
    if (!$username || !$id)
	return -1;
    
    $sql = "DELETE FROM ". $CONF['userpref_table'] 
	   ." WHERE username='$username' AND prefid='$id'";     	 	
    $sth = $dbh->query($sql);
    if (DB::isError($sth)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));
		
	return -1;
    }
    
    return 0;
}

function get_preference(&$error_msg, $dbh, $username, $preference)
{
    global $CONF;
    
    if (!$username)
	return -1;
    
    $sql = "SELECT value, preference FROM ". $CONF['userpref_table'] 
	   ." WHERE username='$username' AND preference='$preference'";     	 	
    $sth = $dbh->query($sql);
    if (DB::isError($sth)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));
		
	return -1;
    }
    
    $row = $sth->fetchRow();	
    if (isset($row[0]))
	return $row[0];
    else 
	return -1;
}

function set_preference(&$error_msg, $dbh, $username, $preference, $value)
{
    global $CONF;

    if (!$username || !$preference)
	return -1;

    $sql = "SELECT COUNT(*) FROM ". $CONF['userpref_table'] 
    	   ." WHERE username='$username' AND preference='$preference'";     	 	
    $sth = $dbh->query($sql);
    if (DB::isError($sth)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		    DB::errorMessage($dbh));
	return -1;
    }
    $row = $sth->fetchRow();	
    // already exists
    if ($row[0] > 0) {
	$sql = "UPDATE ". $CONF['userpref_table']
	       ." SET value = '$value' WHERE username='$username' "
	       ." AND preference = '$preference' ";
    }
    else {
	$sql = "INSERT INTO ". $CONF['userpref_table']
	       ." (preference, value, username) VALUES ("
	       ."'$preference', '$value', '$username')";	 
    }
    
    $sth = $dbh->query($sql);
    if (DB::isError($sth)) {
        if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));
		    
	return -1;	    
    }
    
    return 0;	
}


function required_hits_list($selected_hit)
{
    global $CONF;
    $html = '';
    
    if (!$CONF['required_hits'])
	return "";
    
    $list_values = explode(",", $CONF['required_hits']);    
    
    $html .= "<select name=\"required_hits\">\n";
    
    foreach ($list_values as $val) {
	$val = trim($val);
	$html .= "<option value=\"$val\"";
	if ($val == $selected_hit)
	    $html .= " selected";
	
	$html .= ">$val</option>\n";
    }	    
    $html .= "</select>";
    
    return $html;
}

function print_errors($error_msg)
{
    $html = '';

    if (count($error_msg) < 1)
	return "";
	
    foreach ($error_msg as $error) {
	$html .= "<tr>\n";
	$html .= "  <td colspan=\"2\"><font color=\"red\"><b>"
		  . $error ."</b></font></td>\n";
	$html .= "</tr>\n";
    }
    
    return $html;	
}

function create_spam_rule($username) 
{
    global $CONF;
    $x_spam_found = 0;
    $spam_folder_found = 0;

    $cli = new CLI;
    
    $cli->Login($CONF['cgpro_address'], $CONF['cgpro_port'], 
		$CONF['cgpro_admin'], $CONF['cgpro_admin_password']);
    
    $Rules = $cli->GetAccountRules($username);
    
    foreach ($Rules as $rule) {
	$priority = $rule[0];
	$rule_name = $rule[1];
	$conditions = $rule[2];
	$actions = $rule[3];

	foreach ($conditions as $cond) {
	    foreach ($cond as $co) {
		// if the rule already exists
		if (eregi('x-spam-status', $co))
		    $x_spam_found = 1;
	    }	
	}
    }
    
    if (!$x_spam_found) {
	// add new Rule
	array_push($Rules, array
	    (5, 'SpamFilter',
		array(array('Header Field', 'is', 'X-Spam-Status: Yes*')),
		array(
		    array('Store in', $CONF['spam_folder']),
		    array('Discard')
		)
	    )
	);
	$cli->SetAccountRules($username, $Rules);    		
	
	// add spam folder if it doesn't exist
	$Boxes = $cli->ListMailBoxes(array('accountName'=>$username, 
					    'filter'=>$CONF['spam_folder']));
				     
	foreach($Boxes as $box=>$params) {
    	    if ($box == $CONF['spam_folder'])
		$spam_folder_found = 1;
	}
	
	if (!$spam_folder_found)
	    $cli->CreateMailbox($username, $CONF['spam_folder']);

	// subscribe to the spam folder
	$Subscription = $cli->GetAccountSubscription($username);
    
	$spam_folder_found = 0;
	foreach ($Subscription as $box) {
	    if ($box == $CONF['spam_folder'])
		$spam_folder_found = 1;
	}
	if (!$spam_folder_found) {
	    array_push($Subscription, $CONF['spam_folder']);
	    $cli->SetAccountSubscription($username, $Subscription);
	}
    }    
    
    $cli->Logout();
    
}

function remove_spam_rule($username) 
{
    global $CONF;
    $spam_filter_found = 0;
    $spam_folder_found = 0;

    $cli = new CLI;
    
    $cli->Login($CONF['cgpro_address'], $CONF['cgpro_port'], 
		$CONF['cgpro_admin'], $CONF['cgpro_admin_password']);
    
    $Rules = $cli->GetAccountRules($username);
    
    foreach ($Rules as $key=>$rule) {
	$priority = $rule[0];
	$rule_name = $rule[1];
	$conditions = $rule[2];
	$actions = $rule[3];
	
	if ($rule_name == 'SpamFilter') {
	    $spam_filter_found = 1;
	    unset($Rules[$key]);
	}    
    }
    
    if ($spam_filter_found) {
	$cli->SetAccountRules($username, $Rules);    		

	// unsubscribe to the spam folder
	$Subscription = $cli->GetAccountSubscription($username);
    
	$spam_folder_found = 0;
	foreach ($Subscription as $key=>$box) {
	    if ($box == $CONF['spam_folder']) {
		$spam_folder_found = 1;
		unset($Subscription[$key]);
	    }
	}
	if ($spam_folder_found)
	    $cli->SetAccountSubscription($username, $Subscription);

	// delete the spam folder if it exists
	$Boxes = $cli->ListMailBoxes(array('accountName'=>$username, 
					    'filter'=>$CONF['spam_folder']));
	
	$spam_folder_found = 0;	
	foreach($Boxes as $box=>$params) {
    	    if ($box == $CONF['spam_folder'])
		$spam_folder_found = 1;
	}
	if ($spam_folder_found)
	    $cli->DeleteMailbox($username, $CONF['spam_folder']);

    }    
    
    $cli->Logout();
}

// create the html table with spam tests
function show_tests(&$error_msg, $dbh, $username)
{
    global $CONF;
    $html = '';

    if (!isset($dbh) || !isset($username))
	return;

    $sql = "SELECT prefid, preference, value from ". $CONF['userpref_table']
	    ." WHERE username='$username' AND (preference != 'whitelist_from'"
	    ." AND preference != 'blacklist_from' "
	    ." AND preference != 'required_hits' "
	    ." AND preference != 'spamcgpd_action') "
	    ." ORDER BY preference ASC ";
    $sth = $dbh->query($sql);
    if (DB::isError($dbh)) {
	if ($CONF['debug']) 
	    array_push($error_msg, "Database error: ". 
		DB::errorMessage($dbh));	
	return "";    
    }
    
    while ($row = $sth->fetchRow(DB_FETCHMODE_ASSOC)) {
	$html .= "        <tr bgcolor=\"". $CONF['color'][1] ."\">\n";
	$html .= "          <td>". $row['preference'] ."</td>\n";
	$html .= "          <td align=\"right\">". $row['value'] ."</td>\n";
    	$html .= "          <td><a href='options.php?deltest=". $row['prefid'] 
	    ."'>Delete</a>";
	$html .= "&nbsp;<a href='options.php?edittest=". $row['prefid'] 
	    ."'>Edit</a></td>\n";
	$html .= "        </tr>\n";    	    
    }
    
    return $html;
}

// parse each line in the configuration file
// all locale tests are skipped
function parse_cf_line($line, &$spam_tests)
{
    global $CONF;
    $matches = array();
    
    if (!$line)
	return;

    // name of a test	
    if (preg_match("/^(body|header|full|rawbody|uri)\s+(\S+)\s+.*/i", 
	$line, $matches)) {
	// don't include tests with __ in front, e.g. __MIME_QP
	if (!preg_match("/^__.*/", $matches[2])) {
	    $spam_tests[$matches[2]][2] = $matches[1];
	    return;
	}    
    }	

    unset($matches);	
    // test description
    if (preg_match("/^describe\s+(\S+)\s+(.+)/i", $line, $matches)) {
	if (!preg_match("/^__.*/", $matches[1])) {
	    $spam_tests[$matches[1]][1] = htmlspecialchars($matches[2]);
	    return;
	}    
    }	

    if ($CONF['description_language']) {
	unset($matches);	
	// test description on other language
	$pattern = "/^lang ". $CONF['description_language']
		   ." describe\s+(\S+)\s+(.+)/i";   
	if (preg_match($pattern, $line, $matches)) {
	    if (!preg_match("/^__.*/", $matches[1])) {
		$spam_tests[$matches[1]][3] = htmlspecialchars($matches[2]);
		return;
	    }    
	}	
    }

    unset($matches);	
    // test score
    if (preg_match("/^score\s+(\S+)\s+(.+)\s*/i", $line, $matches)) {
	if (!preg_match("/^__.*/", $matches[1])) {
	    // 4 types of scores
	    if (preg_match("/(\S+)\s+(\S+)\s+(\S+)\s+(\S+)/", $matches[2],
		$scores)) {
		if ($CONF['score_type'] == "local")
		    $spam_tests[$matches[1]][0] = $scores[1];
		else if ($CONF['score_type'] == "net")       
		    $spam_tests[$matches[1]][0] = $scores[2];
		else if ($CONF['score_type'] == "bayes")       
		    $spam_tests[$matches[1]][0] = $scores[3];
		else if ($CONF['score_type'] == "bayesnet")       
		    $spam_tests[$matches[1]][0] = $scores[4];
	    }
	    else	    
		$spam_tests[$matches[1]][0] = $matches[2];
		
	    return;
	}    
    }
}

// read test score, description from .cf files
function read_cf()
{
    global $CONF;
    // $spam_tests['name'][0] - score, $spam_tests['name'][1] - description,
    // $spam_tests['name'][2] - test type: header, body, full, rawbody, uri
    $spam_tests = array();


    // cache spam tests array for a day    
    $cacheLite = new Cache_Lite($CONF['cacheOptions']);    

    // if the value is cached 
    if ($allSpamTests = $cacheLite->get('allSpamTests')) {
	$spam_tests = unserialize($allSpamTests);	
    }
    else {
    
	if (!$CONF['spamassassin_cf_dirs'])
	    return;
    
	$dirs = explode(",", $CONF['spamassassin_cf_dirs']);    
    
	// go through all files in all dirs
	foreach ($dirs as $dir) {
	    $dir = trim($dir);
	    $d = opendir($dir);
	    if (!$d)
		continue;
	
	    while (($file = readdir($d)) !== FALSE) {
		if (($file == '.') || ($file == '..'))
		    continue;
	    		
		$file = "$dir/$file";	
		$fd = fopen("$file", "r");
		while (!feof($fd)) {
		    $line = fgets($fd, 1024);
		
		    if ($line)
			parse_cf_line($line, $spam_tests);	
		}
		fclose($fd);
	    }
	    closedir($d);
	}    
    
	// sort array by test name
	ksort($spam_tests);

	// save spam tests list into the cache
	$allSpamTests = serialize($spam_tests);
	$cacheLite->save($allSpamTests);	
    }

    return $spam_tests;
}

// search for a key in associative array
function in_assoc_array($in_key, $in_array)
{

    foreach ($in_array as $key=>$val) {
	if ($in_key == $key)
	    return true;   
    }
    
    return false;
}

?>

