<?php
$dbData = array(
    'host'  =>  '172.18.0.4',
    'user'  =>  'ninja',
    'pass'  =>  ' \1GV!\19_biW| >e.xZFS*rOQ){b\jO',
    'db'    =>  'ninjaDB_dev',
    'port'  =>  1337
);

$mysqli = new mysqli($dbData['host'], $dbData['user'], $dbData['pass'], $dbData['db'], $dbData['port']);
if ($mysqli->connect_errno) die('Datenbankverbindung fehlgeschlagen, wende dich an den Administrator! (<b>'.$mysqli->connect_errno.':</b>&nbsp;'.$mysqli->connect_error.')');
?>
