<?php

    define('SM_PATH', '../../');
    require_once (SM_PATH . 'include/validate.php');
    require_once (SM_PATH . 'config/config.php');
    require_once (SM_PATH . 'functions/strings.php');
    require_once (SM_PATH . 'functions/page_header.php');

    displayPageHeader($color, 'None');

    require_once(SM_PATH . 'plugins/spamassassin_sql/config.php');
    require_once(SM_PATH . 'plugins/spamassassin_sql/functions.php');
    require_once(SM_PATH . 'plugins/spamassassin_sql/CLI.php');

    global $username, $domain;

    $error_msg = array();
    $error_msg2 = array();
    $action = '';
    $edit = '';
    $delete = '';    
    $editid = '';
    $type = '';
    $address = '';
    $preference = '';
    $spamcgpd_action = $CONF['default_spamcgpd_action'];
    $required_hits = $CONF['default_required_hits'];
    $test_name = '';
    $test_score = '';   
    $deltest = '';
    $edittest = '';

    // get rid of domain
    $username = preg_replace("/@.*/", "", $username);    
    $username = $username .'@'. $domain;

    $CONF['color'][0] = $color[0];
    $CONF['color'][1] = $color[4];    

    $dbh = connect_db();
    if (!$dbh) {
	echo("Error connecting to the database. Aborting.\n");	
	exit;
    }

    sqgetGlobalVar('action', $action, SQ_POST);
    sqgetGlobalVar('delete', $delete, SQ_GET);
    sqgetGlobalVar('edit', $edit, SQ_GET);
    sqgetGlobalVar('editid', $editid, SQ_POST);
    sqgetGlobalVar('address', $address, SQ_POST);
    sqgetGlobalVar('preference', $preference, SQ_POST);
    sqgetGlobalVar('spamcgpd_action', $spamcgpd_action, SQ_POST);
    sqgetGlobalVar('required_hits', $required_hits, SQ_POST);
    sqgetGlobalVar('test_name', $test_name, SQ_POST);
    sqgetGlobalVar('test_score', $test_score, SQ_POST);
    sqgetGlobalVar('deltest', $deltest, SQ_GET);
    sqgetGlobalVar('edittest', $edittest, SQ_GET);
    

    // add or update a white/black list entry
    if (($action == "new") || ($action == "update")) {
	$error = add_white_black($error_msg, $dbh, $username, 
		$action, $editid, $address, $preference);
	// all is OK	
	if (!$error)
	    $address = '';
	// if an error happened and it was the update mode    	
	else if ($action == "update")
	    $edit = $editid;    
    }

    // add or update spam action or required hits
    if ($action == "spam_action") {
	set_preference($error_msg, $dbh, $username, 
	    'spamcgpd_action', $spamcgpd_action);
	set_preference($error_msg, $dbh, $username, 
	    'required_hits', $required_hits);

	// create spam rule into CommuniGate Pro
	if ($spamcgpd_action == 5)	    
	    create_spam_rule($username);
	else
	    remove_spam_rule($username);
	        
    }

    // if in the edit mode
    if ($edit) {
	get_id($error_msg, $dbh, $username, 
	    $edit, $type, $address);
    }
    
    // if in the delete mode
    if ($delete) {
	delete_id($error_msg, $dbh, $username, $delete);
    }
    
    // get user defined spamcgpd_action
    $result = get_preference($error_msg, $dbh, $username, 
			     'spamcgpd_action');	
    if ($result >= 0)
	$spamcgpd_action = $result;

    // get user defined required_hits
    $result = get_preference($error_msg, $dbh, $username, 
			     'required_hits');	
    if ($result >= 0)
	$required_hits = $result;

    // add new spam test score specified by user
    if ($action == "advanced") {
	$test_name = trim($test_name);
	$test_score = trim($test_score);
	
	// solve locale problems
	$test_score = strtr($test_score, ",", ".");
	
	$spam_tests = read_cf();
	// if this test really exists
	if ($spam_tests && !in_assoc_array($test_name, $spam_tests)) 
	    array_push($error_msg2, "Error: there is no test with this name");
	else {
    	    $error = set_preference($error_msg2, $dbh, $username, 
		$test_name, $test_score);
	    if (!$error) {
		$test_name = '';
		$test_score = '';
	    }
	}    	        
    }

    // if in the delete advanced mode
    if ($deltest) {
	delete_id($error_msg2, $dbh, $username, $deltest);
    }

    // if in the edit advanced mode
    if ($edittest) {
	get_id($error_msg2, $dbh, $username, 
	    $edittest, $test_name, $test_score);
    }
    

?>
    
    <script type="text/javascript" language="JavaScript">
	function open_win(url) {
	    var win_width = screen.availWidth - 20;
	    var win_height = screen.availHeight/2;
	    var status_win = 'status=0,width='+win_width+',height='+win_height+',top=10,menubar=1,toolbar=0,resizable=1,scrollbars=1';
	    var new_win = window.open(url,"tests",status_win);
	    if (new_win.opener == null) {
		new_win.opener = self;
	    }
	}
    </script>		
          
<table bgcolor="<?php echo($CONF['color'][0]) ?>" width="95%" 
    align="center" cellpadding="2" cellspacing="0" border="0">
  <tr>
    <td bgcolor="<?php echo($CONF['color'][0]) ?>" align="center">
      <b>Spam Filter Configuration</b><br>
      <table width="100%" cellpadding="5" cellspacing="0" border="0"
	bgcolor="<?php echo($CONF['color'][1]) ?>">          
	<tr>
	  <td align="center">
	  <br>
	  <table width="95%" align="center" border="0">
	    <tr bgcolor="<?php echo($CONF['color'][0]) ?>">
	      <td align="center"><b>White/Black Lists</b></td>
	    </tr>
	    <tr>
	      <td>
	      List below e-mails or domains of message senders 
	      that you wish to be <b>Allowed</b> or <b>Denied</b>
	      regardless of the spam score.
	      <p>
	      Don't insert here one-time addresses that spammers often use.
	      <p>
	      Examples: friend@friend.com, *@mail.com.
	      </td>
	    </tr>
	</table>      
      </tr>
      <tr>
        <td>
	<table border="0" width="95%" align="center">
	  <tr>
	    <td>
	    <table border="0" cellspacing="1" cellpadding="4" 
		bgcolor="<?php echo($CONF['color'][0]) ?>">
	      <tr align="center" bgcolor="<?php echo($CONF['color'][1]) ?>">
	        <td align="left"><b>Address<b></td>
		<td><b>Type</b></td>
		<td><b>Action</b></td>
	      </tr>
<?php echo(show_white_black($error_msg, $dbh, $username)) ?>		      		      	      		      
	    </table>
	    </td>
	  </tr>
	  <tr>
	  <td>
	   <br>
	   <table border="0" cellspacing="1" cellpadding="4" 
		bgcolor="<?php echo($CONF['color'][0]) ?>">
	    <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
	      <form action="options.php" method="post" name="black_white">
	      <input type="hidden" name="action" value="<?php echo($edit ? "update" : "new"); ?>">
	      <input type="hidden" name="editid" value="<?php echo($edit) ?>">             
	      <td colspan="2"><?php echo($edit ? "Edit Address" : "Add New Address") ?></td>
	    </tr>
	    <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
	      <td colspan="2"><?php echo(print_errors($error_msg)) ?></td>
	    </tr>  
	    <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
	      <td>Address:</td>
	      <td><input name="address" type="text" size="40" maxlength="100"
	          value="<?php echo($address) ?>"></td>
	    </tr>
	    <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
	      <td>Type:</td>
	      <td><input type="radio" name="preference"  value="whitelist_from"
	      	   <?php echo(($type && ($type == "whitelist_from")) 
		    ? " checked" : "") ?>>Allow&nbsp;&nbsp;
		  <input type="radio" name="preference" value="blacklist_from"
		   <?php echo((!$type || ($type == "blacklist_from")) ?
			" checked" : "") ?>>Deny
	      </td>
	    </tr>
	    <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
	      <td colspan="2"><input type="submit" value="<?php
	        echo($edit ? "Edit address" : "Add New Address") ?>"
		name="submit"></td>
	    </tr>
	    </form>
	   </table>    	      					
	   </td>
	  </tr>
        </table>
      </td>
    </tr>
	<tr>
	  <td align="center">
	  <table width="95%" align="center" border="0">
	    <tr bgcolor="<?php echo($CONF['color'][0]) ?>">
	      <td align="center"><b>Spam Filter Action</b></td>
	    </tr>
	    <tr>
	      <td>
	      <form action="options.php" method="post" name="spam_act">
	      <input type="hidden" name="action" value="spam_action">
	      <table border="0" cellspacing="1" cellpadding="4"
	         bgcolor="<?php echo($CONF['color'][0]) ?>">	
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="0"
		    <?php echo(($spamcgpd_action == 0) ? " checked" : "") ?>>
		  </td>
		  <td>Disable Spam Filter</td>      
	        </tr>
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="1"
		    <?php echo(($spamcgpd_action == 1) ? " checked" : "") ?>>
		  </td>
		  <td>Default Spam Filter Action (defined by admin)</td>      
	        </tr>
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="2"
		    <?php echo(($spamcgpd_action == 2) ? " checked" : "") ?>>
		  </td>
		  <td>Reject Spam Messages. Send undeliverable notification
		    to the spam sender</td>      
	        </tr>
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="3"
		    <?php echo(($spamcgpd_action == 3) ? " checked" : "") ?>>
		  </td>
		  <td>Silently Delete Spam Messages. No notifications at all.</td>      
	        </tr>
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="4"
		    <?php echo(($spamcgpd_action == 4) ? " checked" : "") ?>>
		  </td>
		  <td>Add Header <b>X-Spam-Status: Yes</b> to the spam 
		    messages.
		    <br>Then you can filter such messages in your mail
		    program, e.g. move them to the special folder.</td>      
	        </tr>
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td align="center">
		    <input type="radio" name="spamcgpd_action" value="5"
		    <?php echo(($spamcgpd_action == 5) ? " checked" : "") ?>>
		  </td>
		  <td>Add Header <b>X-Spam-Status: Yes</b> to the spam 
		    messages and store them into the <b>mail server</b>
		    folder <b><?php echo($CONF['spam_folder']) ?></b>.
		    <br>Messages in this folder older than 14 days are removed 
		    automatically.</td>      
	        </tr>
		<tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td valign="top"><?php echo(required_hits_list($required_hits)) ?></td>
		  <td valign="top"><b>Required Hits</b> - score to identify 
		    message as spam.<br>
		    Once all Spam Filter tests have been run, the resulting 
		    score is matched against this value. And if it's greater 
		    than this value, the e-mail message is marked as spam.
		    <br>
		    Default value is <b><?php echo($CONF['default_required_hits']) ?></b>.    

		<tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td colspan="2">
		    <input type="submit" value="Update Spam Filter Action">
		    <br><br>
		    </form>
		  </td>
		</tr>  
	      </table>    
	      </td>
	    </tr>
	</table>      
      </tr>
    
	<tr>
	  <td align="center">
	  <table width="95%" align="center" border="0">
	    <tr bgcolor="<?php echo($CONF['color'][0]) ?>">
	      <td align="center"><b>Advanced Settings</b></td>
	    </tr>
	    <tr>
	      <td>Here you can set scores for different tests.
	         <br>
	         <a href="javascript:open_win('tests.php')"><b>Click here</b></a> 
	         to open the tests list. Click on any test on that page 
		 and test name and score will appear in the appropriate 
		 fields of this form.
		 <br>
		 In order to disable any test set its score to 0.
	      	<br><br>    
	      </td>	
	    </tr>
	    <tr>
	      <td>
	      <table border="0" cellspacing="1" cellpadding="4"
	         bgcolor="<?php echo($CONF['color'][0]) ?>">
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td><b>Test name</b></td>
		  <td><b>Score</b></td>
		  <td align="center"><b>Action</b></td>
		</tr>
		<?php echo(show_tests($error_msg, $dbh, 
				      $username)) ?>
	      </table>				      
	      </td>					      
	    </tr>
	    <tr>
	      <td><?php echo(print_errors($error_msg2)) ?></td>
	    </tr>  
	    <tr>
	      <td>
	      <form action="options.php" method="post" name="adv_form">
	      <input type="hidden" name="action" value="advanced">
	      <table border="0" cellspacing="1" cellpadding="4"
	         bgcolor="<?php echo($CONF['color'][0]) ?>">	
	        <tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td>Test name:</td>    
		  <td>
		    <input type="text" name="test_name" value="<?php
		    echo($test_name) ?>" size="40">
		  </td>
		  <td>Score:</td>      
		  <td><input type="text" name="test_score" value="<?php
		    echo($test_score) ?>" size="5"></td>
	        </tr>
		<tr bgcolor="<?php echo($CONF['color'][1]) ?>">
		  <td colspan="4">
		    <input type="submit" value="Update Advanced Settings">
		  </td>
		</tr>  
	      </table>    
	      <br><br>
	      </td>
	    </tr>
	</table>      
      </tr>

    
    
   </table>       	   
   </td>
  </tr>
</table>     	      
	      
</body>
</html>
