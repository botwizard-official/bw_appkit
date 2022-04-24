<?php

namespace Appkit;

class LaunchUtil {

    const CIPHER = 'AES-128-CBC';

    private function __construct() {
        
    }

    /**
     * 
     * @param string $appSecret
     * @param string $randomSalt
     * @param string $ciphertextHex
     * @return string
     */
    public static function decryptLaunchParameter(
            $appSecret, $randomSalt, $ciphertextHex) {
        $key = sha1($appSecret . $randomSalt, true);
        $ivlen = openssl_cipher_iv_length(self::CIPHER);
        $ciphertext = hex2bin($ciphertextHex);
        $iv = substr($ciphertext, 0, $ivlen);
        $ciphertextRaw = substr($ciphertext, $ivlen);
        return openssl_decrypt($ciphertextRaw,
                self::CIPHER, $key, OPENSSL_RAW_DATA, $iv);
    }

    /**
     * 
     * @param array $p
     * @param string $salt
     * @param string $appSecret
     * @return string
     */
    public static function calcAppLaunchSign(array $p, $salt, $appSecret) {
        $params = [
            'app_id' => strval($p['app_id'] ?? ''),
            'client_id' => strval($p['client_id'] ?? ''),
            'viewer_id' => strval($p['viewer_id'] ?? ''),
            'botid' => strval($p['botid'] ?? ''),
            'access_token' => strval($p['access_token'] ?? ''),
        ];
        ksort($params);
        $strings = array_merge([$salt, $appSecret],
                array_map('strval', $params));
        return md5(implode(':', $strings));
    }

}
