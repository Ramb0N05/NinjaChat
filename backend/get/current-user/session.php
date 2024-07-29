<?php
if (isset($_POST['session_identifier']) && !empty($_POST['session_identifier']) && $session_identifier = $_POST['session_identifier']
)
	die(json_encode(getChatSession($mysqli, $session_identifier)));
else die(json_encode([false]));
?>
