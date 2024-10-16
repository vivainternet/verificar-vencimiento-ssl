<?php

function verificarVencimientoSSL($url)
{
	$orignal_parse = parse_url($url, PHP_URL_HOST);
	$get  = stream_context_create(array("ssl" => array("capture_peer_cert" => TRUE)));

	$read = stream_socket_client("ssl://" . $orignal_parse . ":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

	$cert = stream_context_get_params($read);
	$certinfo = openssl_x509_parse($cert['options']['ssl']['peer_certificate']);

	$valid_from = date(DATE_RFC2822, $certinfo['validFrom_time_t']);
	// $valid_to 	= date(DATE_RFC2822,$certinfo['validTo_time_t']);
	$valid_to = date('Y-m-d H:i:s', $certinfo['validTo_time_t']); // Otro formato de fecha

	echo $url . '<br>';
	// echo "Valido desde: ".$valid_from."<br>";
	echo "Valido hasta: " . $valid_to . "<br>";

	echo $certinfo['issuer']['O']; // Muestra empresa de SSL
	// Debug: Muestra Array completo del certificado
	// echo '<pre>'; print_r($certinfo); echo '</pre>';
}

$url = "https://www.vivainternet.com"; // Reemplaza con la URL que deseas verificar
verificarVencimientoSSL($url);
