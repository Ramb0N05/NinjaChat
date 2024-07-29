<?php
if ($CERT && isset($_GET['type']) && !empty($_GET['type']) && $type = $_GET['type']) {
	switch($type) {
		case 'adv-message':
			require_once('./get/session/adv-message.php');
			break;
		
		default:
			die(json_encode([false]));
	}
}
?>
