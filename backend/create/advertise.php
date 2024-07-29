<?php
if ($CERT != false && (
		isset($_POST['session_identifier']) &&
		!empty($_POST['session_identifier']) &&
		$session_identifier = $_POST['session_identifier']
	) && (
		isset($_POST['encrypted_key']) &&
		!empty($_POST['encrypted_key']) &&
		$encrypted_key = $_POST['encrypted_key']
	) && (
		isset($_POST['encrypted_message']) &&
		!empty($_POST['encrypted_message']) &&
		$encrypted_message = $_POST['encrypted_message']
	)
) {
	die(json_encode([
		createChatMessage($mysqli, $session_identifier, $encrypted_key, $encrypted_message),
		$session_identifier, $encrypted_key, $encrypted_message
	]));
} else die(json_encode([false, 'missing parameters or permission', $_POST]));
?>
