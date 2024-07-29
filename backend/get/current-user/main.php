<?php
if (isset($_GET['type']) && !empty($_GET['type']) && $type = $_GET['type']) {
	switch($type) {
		case 'info':
			die(json_encode($ACL));
			break;
			
		case 'cert-info':
			die(json_encode($CERT));
			break;
			
		case 'messages':
			require_once('./get/current-user/messages.php');
			break;
		
		case 'session':
			require_once('./get/current-user/session.php');
			break;
		
		case 'settings':
			require_once('./get/current-user/settings.php');
			break;
		
		default:
			die(json_encode([false]));
	}
}
?>
