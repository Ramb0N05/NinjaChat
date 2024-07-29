<?php
if ($CERT &&
	(
		isset($_POST['session_identifier']) &&
		!empty($_POST['session_identifier']) &&
		$session_identifier = $_POST['session_identifier']
	) && (
		isset($_POST['session_public_key']) &&
		!empty($_POST['session_public_key']) &&
		$public_key = $_POST['session_public_key']
	)
) {
	$session_expire = (isset($_POST['session_expire']) && is_numeric($_POST['session_expire']) ? (int)$_POST['session_expire'] : 86400);
	if ($session_expire < 0 || $session_expire > 86400) $session_expire = 86400;

	if (createChatSession($mysqli, $session_identifier, $public_key, $session_expire))
		die(json_encode([true]));
	else die(json_encode([false, 'cannot create session']));
} else die(json_encode([false, 'missing params']));
?>
