<?php

include_once("config.php");
include_once("functions.php");

    // read in array with spam tests
    $spam_tests = read_cf();

    if (!$spam_tests)
	exit(1);
	
?>

<html>
<head>
    <meta http-equiv="Content-type" content="text/html">
    <title>Spam Filter Tests</title>
    <style type="text/css">
    <!--
    body, td {
	font-family: Verdana, Geneva, Arial, Helvetica, san-serif;
	font-size: 10pt;
    }
    -->
    </style>		
    <script type="text/javascript" language="JavaScript">
	function t(test_name, test_score) {
	    opener.document.adv_form.test_name.value = test_name;
	    opener.document.adv_form.test_score.value = test_score;	    
	}
    </script>	       
</head>    

<body text="black" bgcolor="white">

<table bgcolor="<?php echo($CONF['color'][0]) ?>" width="95%" 
    align="center" cellpadding="2" cellspacing="0" border="0">
  <tr>
    <td bgcolor="<?php echo($CONF['color'][0]) ?>" align="center">
      <b>Spam Filter Tests</b><br>
      <table width="100%" cellpadding="5" cellspacing="0" border="0"
	bgcolor="<?php echo($CONF['color'][1]) ?>">          
	<tr>
	  <td align="center">
	  <table width="95%" align="center" border="0" cellspacing="1"
	    cellpadding="3" bgcolor="<?php echo($CONF['color'][0]) ?>">
	    <tr align="center" bgcolor="white">
	      <td><b>Area tested</b></td>
	      <td><b>Description of test</b></td>
	      <td><b>Test name</b></td>
	      <td><b>Spam&nbsp;Score</b></td>
	    </tr>  
<?php

    foreach ($spam_tests as $name=>$val) {
	echo "<tr bgcolor=\"white\">\n";	
	echo "  <td>". (isset($val[2]) ? $val[2] : "&nbsp;") ."</td>\n";
	echo "  <td>". 
	(isset($val[3]) ? $val[3] : (isset($val[1]) ? $val[1] : "&nbsp;")) 
	."</td>\n";
	echo "  <td><a href=\"javascript:t('$name', '" 
	     . (isset($val[0]) ? $val[0] : "") . "')\">$name</a></td>\n";
	echo "  <td align=\"right\">". 
		(isset($val[0]) ? $val[0] : "&nbsp;") ."</td>\n";	
	echo "</tr>\n";
    }

?>

        </table>
        </td>
      </tr>
      <tr>
        <td align="center">
	<form>
	    <input type="button" value="Close Window" onClick="window.close()">
	    <br><br>
	</td>
      </tr>		
    </table>
    </td>
  </tr>
</table>

</body>
</html>

          	  
