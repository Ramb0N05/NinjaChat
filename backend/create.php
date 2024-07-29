<?php
header('Content-Type: application/json');
require_once('_init.php');

if ($CERT && isset($_GET['type']) && !empty($_GET['type']) && $type = $_GET['type']) {
	switch($type) {
		case 'message':
			require_once('./create/message.php');
			break;
			
		case 'session':
			require_once('./create/session.php');
			break;
			
		case 'advertise':
			require_once('./create/advertise.php');
			break;
		
		default:
			die(json_encode([false, 'invalid type']));
	}
} else {
	die(json_encode([false]));
}
?>
