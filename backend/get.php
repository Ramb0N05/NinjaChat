<?php
header('Content-Type: application/json');
require_once('_init.php');

if (isset($_GET['realm']) && !empty($_GET['realm']) && $realm = $_GET['realm']) {
	switch($realm) {
		case 'current-user':
			require_once('./get/current-user/main.php');
			break;
			
		case 'user':
			require_once('./get/user/main.php');
			break;
			
		case 'session':
			require_once('./get/session/main.php');
			break;
		
		default:
			die(json_encode([false]));
	}
}
?>
