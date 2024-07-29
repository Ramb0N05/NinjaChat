<?php
if ($CERT) {
	$chat_messages = getChatMessages($mysqli, $CERT);
	die(json_encode($chat_messages));
}
?>
