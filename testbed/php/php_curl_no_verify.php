<?php // rule: megasast/php-curl-no-verify
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
?>