<?php

include_once("config.php");
include_once("functions.php");


    $domain = '';
    $login = '';
    $password = '';
    $click = '';
    $error = '';
    $logout = '';


    // logout destroys all the session data
    if (isset($_GET['logout'])) {
	session_start();
	$_SESSION = array();
	session_destroy();
    }    
    
    if (isset($_POST['domain']))
	$domain = $_POST['domain'];
    if (isset($_POST['login'])) {
	$login = trim($_POST['login']);
	// strip domain
	$login = preg_replace("/@.*/", "", $login);	
    }	
    // create account login in the form login@domain
    $username = $login."@".$domain;
    
    if (isset($_POST['password']))
	$password = trim($_POST['password']);
    if (isset($_POST['click']))
	$click = $_POST['click'];
    	
    
    if ($click) {
	if (authenticate_user($username, $password))
	    $error = "Login unsuccessful";
	else {
	    session_start();
	    $_SESSION['username'] = $username;
	    
	    if (isset($_SESSION['username'])) {
		// redirect to the sa page
		header("Location: sa.php");
		exit;
	    }	
	}    
    }
    
?>
<html>
<head>
    <meta http-equiv="Content-type" content="text/html">
    <title>Spam Filter settings login</title>
    <style type="text/css">
    <!--
    body, td {
	font-family: Verdana, Geneva, Arial, Helvetica, san-serif;
	font-size: 10pt;
    }
    -->
    </style>		
</head>    

<body text="black" bgcolor="white">

<form action="index.php" method="post">
<table bgcolor="white" border="0" cellspacing="0" cellpadding="0" width="100%">
  <tr>
    <td align="center">    
      <table bgcolor="white" border="0" width="350">
        <tr>
	  <td><br><br></td>
	</tr>
        <tr>
	  <td bgcolor="#dcdcdc" align="center"><b>Spam Filter settings login</b></td>
	</tr>
        <tr>
	  <td bgcolor="white" align="left">
	    <table bgcolor="white" align="center" border="0" width="100%">
	      <tr>
	        <td align="right" width="30%">Login:</td>
	        <td><input type="text" name="login" value="<?php echo($login) ?>"></td>
	      </tr>
	      <tr>	
		<td align="right" width="30%">Domain:</td>
		<td><?php echo(list_all_domains($domain)) ?></td>
	      </tr>	
	      <tr>
		<td align="right" width="30%">Password:</td>
		<td><input type="password" name="password" value="<?php echo($password) ?>"></td>
	      </tr>
	      <tr>
	        <td colspan="2" align="center">
		<?php echo("<font color=\"red\">$error</font>") ?></td>
	      </tr>
	      <tr>
	        <td colspan="2" align="center">
		  <input type="hidden" name="click" value="1">    
		  <input type="submit" value="Login">
		</td>
	      </tr>
	    </table>
          </td>
	</tr>
      </table>
    </td>
  </tr>
</table>
        		

</body>	  	      		
</html>
		
			



