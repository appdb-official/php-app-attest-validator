<?php

namespace Appdb\Attestvalidator;


class AttestValidator
{

    /**
     * @param string $binary Binary representation of a certificate
     * @return false|\OpenSSLCertificate
     */
    static function makeCert(string $binary)
    {
        $encoded = base64_encode($binary);

        $cert = "-----BEGIN CERTIFICATE-----\n" . implode("\n", str_split($encoded, 64)) . "\n-----END CERTIFICATE-----\n";

        return openssl_x509_read($cert);
    }

    /**
     * @param string $assertion Base64-encoded assertion
     * @param string $client_data Data that was asserted
     * @param string $key_pem PEM-encoded private key that was used to generate assertion
     * @param string $appIdHashHex HEX of app ID hash
     * @param int $previous_counter Previous assertion counter
     * @return array [result int 1=pass, 0=fail, error nullable string error code, counter int assertion counter, exception nullable exception object]
     */
    static function validateAssertion(string $assertion, string $client_data, string $key_pem, string $appIdHashHex, int $previous_counter = 0): array
    {
        try {
            $decoder = \CBOR\Decoder::create();
            $inputStream = new \CBOR\StringStream(base64_decode($assertion));
            $cborData = $decoder->decode($inputStream);
            $data = $cborData->normalize();
        } catch (Exception $e) {
            return ['result' => 0, 'error' => 'ERROR_ASSERTION_IS_INVALID', 'exception' => $e, 'counter' => 0];
        }
        $client_data_hash = hex2bin(hash("sha256", $client_data));
        $nonce = hex2bin(hash('sha256', $data['authenticatorData'] . $client_data_hash));
        $public_key = openssl_pkey_get_public($key_pem);
        $is_signature_valid = openssl_verify($nonce, $data['signature'], $public_key, OPENSSL_ALGO_SHA256);
        if ($is_signature_valid !== 1) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_DATA_SIGNATURE', 'exception' => null, 'counter' => 0];
        }
        $authData = $data['authenticatorData'];
        //var_dump($authData);
        $rpId = substr($authData, 0, 32);
        $appIdHash = hex2bin($appIdHashHex);
        if ($appIdHash !== $rpId) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_ASSERTION', 'exception' => null, 'counter' => 0];
        }
        $counter = substr($authData, 33, 4);
        $counter = hexdec(bin2hex($counter));
        if ($counter <= $previous_counter) {
            return ['result' => 0, 'error' => 'ERROR_OLD_ASSERTION', 'exception' => null, 'counter' => $counter];
        }

        return ['result' => 1, 'counter' => $counter, 'error' => null, 'exception' => null];
    }

    /**
     * @param string $attestation Base64 encoded attestation data
     * @param string $challenge The challenge used to generate data
     * @param string $keyId Base64 encoded keyId
     * @param string $appIdHashHex HEX of app ID hash
     * @param bool $isTestDevice Is testing device or not, default 0
     * @return array [result int 1=pass, 0=fail, error nullable string error code, exception nullable exception object]
     */
    static function validateAttestation(string $attestation, string $challenge, string $keyId, string $appIdHashHex, bool $isTestDevice = false): array
    {
        $app_attest_root_pem = '-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----
';
        /*
         * Decode the attestation
         */
        $decoder = \CBOR\Decoder::create();
        $inputStream = new \CBOR\StringStream(base64_decode($attestation));
        try {
            $cborData = $decoder->decode($inputStream);
            $data = $cborData->normalize();
        } catch (Exception $e) {
            return ['result' => 0, 'error' => 'ERROR_ATTESTATION_IS_INVALID', 'exception' => $e];
        }

        if (($data['fmt'] ?? '') !== 'apple-appattest') {
            return ['result' => 0, 'error' => 'ERROR_NOT_APPLE_ATTESTATION', 'exception' => null];
        }

        /*
         * Extract useful attestation data
         */
        $attStmt = $data['attStmt'] ?? [];

        $x5c = $attStmt['x5c'] ?? [];
        $receipt = $attStmt['receipt'] ?? '';
        $authData = $data['authData'] ?? '';

        $rpId = substr($authData, 0, 32);
        $counter = substr($authData, 33, 4);
        $aaguid = substr($authData, 37, 16);
        $credentialIdLength = substr($authData, 53, 2);
        $credentialId = substr($authData, 55, unpack('n', $credentialIdLength)[1]);

        if (empty($attStmt) || empty($x5c) || empty($receipt) || empty($authData)) {
            return ['result' => 0, 'error' => 'ERROR_INCOMPLETE_ATTESTATION_DATA', 'exception' => null];
        }

        // Step 1: verify certificates
        $credCert = self::makeCert($x5c[0]);

        $certChain = array_map(fn($c) => self::makeCert($c), $x5c);
        $certChain[] = openssl_x509_read($app_attest_root_pem);

        foreach (range(1, count($certChain) - 1) as $i) {
            if (!openssl_x509_verify($certChain[$i - 1], $certChain[$i])) {
                return ['result' => 0, 'error' => 'ERROR_INVALID_ATTESTATION_CERTIFICATES', 'exception' => null];
            }
        }

        /*
         * Step 2 + 3: create clientDataHash as the challenge hash appended to the authData
         */

        $clientDataHash = hash('sha256', $authData . hash('sha256', $challenge, true));

        /*
         * Step 4: Obtain the value of the credCert extension with OID 1.2.840.113635.100.8.2,
         */

        $parsedCert = openssl_x509_parse($credCert);
        $extension = $parsedCert['extensions']['1.2.840.113635.100.8.2'] ?? '';

        // The extension is a DER-encoded ASN.1 sequence, to avoid an ASN.1 decoding library I use a workaround
        // The first 6 bytes that represent the apn wrapping of a string, we can ignore them
        // The remaining bytes represent the actual string inside the sequence
        $extension = bin2hex(substr($extension, 6));

        if ($extension !== $clientDataHash) {
            return ['result' => 0, 'error' => 'ERROR_ATTESTATION_HASH_IS_INVALID', 'exception' => null];
        }

        /*
         * Step 5: Create the SHA256 hash of the public key in credCert,
         * and verify that it matches the key identifier from your app
         */
        $publicKey = openssl_pkey_get_public($credCert);

        $pKey = openssl_pkey_get_details($publicKey);

        // Create the X9.62 uncompressed point format bytes as: https://security.stackexchange.com/a/185552
        // Basically, get the EC x and y params, concatenate them and prepend with 0x04
        if (!isset($pKey['ec'])) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_PUBLIC_KEY', 'exception' => null];
        }

        $pBytes = "\x04" . $pKey['ec']['x'] . $pKey['ec']['y'];
        if (hash('sha256', $pBytes, true) !== $credentialId) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_PUBLIC_KEY', 'exception' => null];
        }

        /*
         * Step 6: Calculate the App ID hash and check it is equal to RP ID
         */
        $appIdHash = hex2bin($appIdHashHex);

        if ($appIdHash !== $rpId) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_APP_ID_HASH', 'exception' => null];
        }

        /*
         * Step 7: verify the counter is 0
         */
        if ($counter !== "\0\0\0\0") {
            return ['result' => 0, 'error' => 'ERROR_INVALID_ATTESTATION_COUNTER', 'exception' => null];
        }

        /*
         * Step 8: verify the aaguid field
         */
        if (!in_array(
            $aaguid,
            $isTestDevice
                ? ['appattestdevelop', "appattest\0\0\0\0\0\0\0"]
                : ["appattest\0\0\0\0\0\0\0"]
        )
        ) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_ATTESTATION_ENVIRONMENT', 'exception' => null];
        }

        /*
         * Step 9: verify that credentialId is the same as the key identifier
         */
        if ($credentialId !== base64_decode($keyId)) {
            return ['result' => 0, 'error' => 'ERROR_INVALID_ATTESTATION_KEY_ID', 'exception' => null];
        }

        return ['result' => 1, 'error' => null, 'exception' => null];
    }
}
