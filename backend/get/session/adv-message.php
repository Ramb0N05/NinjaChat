<?php
if ($CERT != false && isset($_POST['session_identifier']) && !empty($_POST['session_identifier']) && $session_identifier = $_POST['session_identifier']) {
	$messages = getChatMessages($mysqli, $session_identifier);
	if (isset($messages) && is_array($messages) && count($messages) === 1) {
		die(json_encode($messages));
	} else die(json_encode([false, 'no advertise found']));
} else die(json_encode([false, 'missing parameter or permission']));
?>
