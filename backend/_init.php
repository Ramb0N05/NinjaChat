<?php
error_reporting(E_ALL);

require_once('../config.php');
require_once('../../inc/functions.inc.php');
require_once('../inc/chat_functions.inc.php');

$CERT	= getClientCert();
$ACL	= getAclInfo($mysqli, $CERT);
?>
