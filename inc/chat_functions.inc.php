<?php
function getChatSession($mysqliConn, $session_identifier) {
	$sql = "SELECT * FROM `chat__sessions` WHERE `identifier`='$session_identifier'";
	$result = $mysqliConn->query($sql);
	
	if ($result && $result->num_rows === 1)
		return $result->fetch_assoc();
	else return false;
}

function createChatSession($mysqliConn, $session_identifier, $session_public_key, $session_expire) {
	$session_expire = ($session_expire === 0 ? null : time() + $session_expire);
	$sql = "INSERT INTO `chat__sessions` (`identifier`, `expire`, `pub_key`)
			VALUES ('$session_identifier', '$session_expire', '$session_public_key')";
	return $mysqliConn->query($sql);
}

function getChatMessages($mysqliConn, $client) {
	$chat_messages = null;
	if (is_string($client) && strlen($client) == 32)
		$recipient_identifier = hash('sha256', $client);
	elseif (is_array($client))
		$recipient_identifier = hash('sha256', $client['name'].$client['tag'].$client['serial']);
	else $recipient_identifier = null;
	
	if (!empty($recipient_identifier)) {
		$sql = "SELECT * FROM `chat__messages` WHERE `recipient_identifier`='$recipient_identifier'";
		$result = $mysqliConn->query($sql);
		
		if ($result && $result->num_rows > 0) {
			while ($message = $result->fetch_assoc()) {
				$chat_messages[] = [
					'encrypted_key'		=> $message['encrypted_key'],
					'encrypted_message'	=> $message['encrypted_message']
				];
			}
		}
	} else $chat_messages = false;
	
	return $chat_messages;
}

function createChatMessage($mysqliConn, $recipient, $encrypted_key, $encrypted_message) {
	if (is_string($recipient) && strlen($recipient) == 32)
		$recipient_identifier = hash('sha256', $recipient);
	elseif (is_array($recipient))
		$recipient_identifier = hash('sha256', $recipient['name'].$recipient['tag'].$recipient['serial']);
	else $recipient_identifier = null;
	
	if (!empty($recipient_identifier) && !empty($encrypted_key) && !empty($encrypted_message)) {
		$sql = "INSERT INTO `chat__messages` (`recipient_identifier`, `encrypted_key`, `encrypted_message`)
				VALUES ('$recipient_identifier', '$encrypted_key', '$encrypted_message')";
		$result = $mysqliConn->query($sql);
		$error = $mysqliConn->error;
		
		return [$result, $error];
	} else return false;
}


?>