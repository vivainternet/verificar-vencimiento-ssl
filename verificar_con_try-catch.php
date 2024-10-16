<?php

function verificarVencimientoSSL($url) {
	try {
			// Crear un contexto de flujo para realizar la solicitud
			$get = stream_context_create(['ssl' => [
							'capture_peer_cert' => TRUE
					]
			]);

			// Obtener el contenido de la URL a través de un flujo
			$orignal_parse = parse_url($url, PHP_URL_HOST);
			$read = stream_socket_client("ssl://".$orignal_parse.":443", $errno, $errstr, 30, STREAM_CLIENT_CONNECT, $get);

			if (!$read) {
					throw new Exception("Error al conectar: {$errstr} ($errno)");
			}

			// Obtener la información del certificado del flujo
			$cert = stream_context_get_params($read)['options']['ssl']['peer_certificate'];

			// Decodificar el certificado en formato PEM
			//openssl_x509_read($cert, $x509cert);

			// Obtener la fecha de vencimiento del certificado
			$fechaVencimiento = openssl_x509_parse($cert)['validTo_time_t'];

			// Convertir la fecha a un formato legible
			$fechaVencimientoFormateada = date('Y-m-d H:i:s', $fechaVencimiento);

			return $fechaVencimientoFormateada;
	} catch (Exception $e) {
			// Manejar diferentes tipos de excepciones si es necesario
			if ($e->getMessage() === 'failed to open stream: could not connect to server') {
					echo "No se pudo conectar al servidor.";
			} else if (strpos($e->getMessage(), 'error:14090086') !== false) {
					echo "El certificado SSL no es válido.";
			} else {
					echo "Error desconocido: " . $e->getMessage();
			}
	}
}

// Ejemplo de uso
$url = "https://www.google.com.ar"; // Reemplaza con la URL que deseas verificar
$fechaVencimiento = verificarVencimientoSSL($url);

if ($fechaVencimiento) {
	echo "El certificado SSL de {$url} vence el: {$fechaVencimiento}";
} else {
	echo "No se pudo obtener la información del certificado SSL";
}

?>