<?php

declare(strict_types=1);

namespace WOWSRP;

use GMP;

class SRP
{
    /**
     * @var GMP [N] Constant
     */
    public GMP $N;

    /**
     * @var GMP [g] Constant
     */
    public GMP $g;

    /**
     * @var GMP [k] Constant
     */
    public GMP $k;

    /**
     * @var GMP little endian of 20 bytes
     */
    public GMP $xor;

    /**
     * @var string Hash lib name
     */
    public string $hasher;

    public function __construct(
        ?GMP $N = null,
        ?GMP $g = null,
        ?GMP $k = null,
        ?GMP $xor = null,
        ?string $hasher = null
    )
    {
        $this->k = $k ?? gmp_init(3, 10);
        $this->g = $g ?? gmp_init(7, 10);
        $this->N = $N ?? gmp_init('894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7', 16);
        $this->xor = $xor ?? gmp_init('A7C27B6C96CA6F505A7C98031173AC383AB07BDD', 16);
        $this->hasher = $hasher ?? 'sha1';
    }

    /**
     * [x] = sha1( s | sha1( U | : | p ))
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_x_salt_values.txt
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_x_values.txt
     *
     * @param string $username
     * @param string $password
     * @param string $salt little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 20 bytes
     */
    public function calculate_x(string $username, string $password, string $salt): string
    {
        $username = strtoupper($username);
        $password = strtoupper($password);

        $interim = $this->hash("{$username}:{$password}", true);

        $hash = $this->hash(strrev($salt) . $interim, true);

        return strrev($hash);
    }

    /**
     * [v] = g^x % N
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_v_values.txt
     *
     * @param string $username
     * @param string $password
     * @param string $salt little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 32 bytes
     */
    public function calculate_password_verifier(string $username, string $password, string $salt): string
    {
        $x = $this->calculate_x($username, $password, $salt);

        $x = gmp_import($x, 1, GMP_MSW_FIRST);

        $pow = gmp_powm($this->g, $x, $this->N);

        return gmp_export($pow, 1, GMP_MSW_FIRST);
    }

    /**
     * [B] = (k * v + (g^b % N)) % N
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_B_values.txt
     *
     * @param string $verifier little endian binary string of 32 bytes
     * @param string $serverPrivateKey little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 32 bytes
     */
    public function calculate_server_public_key(string $verifier, string $serverPrivateKey): string
    {
        $v = gmp_import($verifier, 1, GMP_MSW_FIRST);
        $b = gmp_import($serverPrivateKey, 1, GMP_MSW_FIRST);

        $B = gmp_mod(gmp_add(gmp_mul($this->k, $v), gmp_powm($this->g, $b, $this->N)), $this->N);

        return gmp_export($B, 1, GMP_MSW_FIRST);
    }

    /**
     * [S] = (B - (k * (g^x % N)))^(a + u * x) % N
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_client_S_values.txt
     *
     * @param string $clientPrivateKey little endian binary string of 32 bytes
     * @param string $serverPublicKey little endian binary string of 32 bytes
     * @param string $x little endian binary string of 32 bytes
     * @param string $u little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 32 bytes
     */
    public function calculate_client_s_key(string $clientPrivateKey, string $serverPublicKey, string $x, string $u): string
    {
        $a = gmp_import($clientPrivateKey, 1, GMP_MSW_FIRST);
        $B = gmp_import($serverPublicKey, 1, GMP_MSW_FIRST);
        $x = gmp_import($x, 1, GMP_MSW_FIRST);
        $u = gmp_import($u, 1, GMP_MSW_FIRST);

        $S = gmp_powm((gmp_sub($B, gmp_mul($this->k, gmp_powm($this->g, $x, $this->N)))), (gmp_add($a, gmp_mul($u, $x))), $this->N);

        return gmp_export($S, 1, GMP_MSW_FIRST);
    }

    /**
     * [S] = (A * (v^u % N))^b % N
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_S_values.txt
     *
     * @param string $A
     * @param string $v
     * @param string $u
     * @param string $b
     *
     * @return string little endian binary string of 32 bytes
     */
    public function calculate_server_s_key(string $A, string $v, string $u, string $b): string
    {
        $A = gmp_import($A, 1, GMP_MSW_FIRST);
        $v = gmp_import($v, 1, GMP_MSW_FIRST);
        $u = gmp_import($u, 1, GMP_MSW_FIRST);
        $b = gmp_import($b, 1, GMP_MSW_FIRST);

        $S = gmp_powm(($A * gmp_powm($v, $u, $this->N)), $b, $this->N);

        return gmp_export($S, 1, GMP_MSW_FIRST);
    }

    /**
     * [u] = sha1( A | B )
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_u_values.txt
     *
     * @param string $A little endian binary string of 32 bytes
     * @param string $B little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 20 bytes
     */
    public function calculate_u(string $A, string $B): string
    {
        $A = strrev($A);
        $B = strrev($B);

        return strrev(sha1($A . $B, true));
    }

    /**
     * [K] = SHA_Interleave(S)
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_interleaved_values.txt
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_split_s_key.txt
     *
     * @param string $s little endian binary string of 32 bytes
     *
     * @return string binary string of 40 bytes
     */
    public function calculate_interleaved(string $s): string
    {
        $s = strrev($s);
        $length = strlen($s);

        for ($i = 0; $i < $length; $i++)
        {
            if ($s[$i] !== "\x00" && ($length - $i) % 2 === 0)
            {
                if ($i === 0)
                {
                    break;
                }
                else
                {
                    $s = substr($s, $i);
                    break;
                }
            }
        }

        $E = '';
        $F = '';

        for ($i = 0; $i < strlen($s); $i++)
        {
            $i % 2 === 0
                ? $E .= $s[$i]
                : $F .= $s[$i];
        }

        $G = $this->hash($E, true);
        $H = $this->hash($F, true);
        $K = '';

        for ($i = 0; $i < 20; $i++)
        {
            $K[$i * 2] = $G[$i];
            $K[$i * 2 + 1] = $H[$i];
        }

        return strrev($K);
    }

    /**
     * [M2] = sha1(A | M1 | K)
     *
     * @param string $A little endian binary string of 32 bytes
     * @param string $M1 little endian binary string of 20 bytes
     * @param string $K little endian binary string of 40 bytes
     *
     * @return string little endian binary string of 20 bytes
     */
    public function calculate_server_proof(string $A, string $M1, string $K): string
    {
        $A = strrev($A);
        $M1 = strrev($M1);
        $K = strrev($K);

        return strrev(sha1($A . $M1 . $K, true));
    }

    /**
     * [M1] = sha1( X | sha1(U) | s | A | B | K )
     *
     * @param string $username
     * @param string $K little endian binary string of 40 bytes
     * @param string $A little endian array of 32 bytes
     * @param string $B little endian binary string of 32 bytes
     * @param string $s little endian binary string of 32 bytes
     *
     * @return string binary string of 20 bytes
     */
    public function calculate_client_proof(string $username, string $K, string $A, string $B, string $s): string
    {
        $X = gmp_export($this->xor, 1, GMP_LSW_FIRST);
        $U = $this->hash(strtoupper($username), true);
        $s = strrev($s);
        $A = strrev($A);
        $B = strrev($B);
        $K = strrev($K);

        $M1 = $this->hash($X . $U . $s . $A . $B . $K, true);

        return strrev($M1);
    }

    /**
     * [A] = g^a % N
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_A_values.txt
     *
     * @param string $a little endian binary string of 32 bytes
     *
     * @return string little endian binary string of 32 bytes
     */
    public function calculate_client_public_key(string $a): string
    {
        $a = gmp_import(strrev($a), 1, GMP_LSW_FIRST);
        $pow = gmp_powm($this->g, $a, $this->N);

        return gmp_export($pow, 1, GMP_MSW_FIRST);
    }

    /**
     * sha1( username | client_data | server_data | session_key )
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/calculate_reconnection_values.txt
     *
     * @param string $username
     * @param string $clientData little endian binary string of 16 bytes
     * @param string $serverData little endian binary string of 16 bytes
     * @param string $sessionKey little endian binary string of 40 bytes
     *
     * @return string little endian binary string of 20 bytes
     */
    public function calculate_reconnect_proof(string $username, string $clientData, string $serverData, string $sessionKey): string
    {
        $hash = $this->hash(
            $username .
            strrev($clientData) .
            strrev($serverData) .
            strrev($sessionKey),
            true
        );

        return strrev($hash);
    }

    /**
     * [E] = (x ^ S) + L
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/encryption/calculate_encrypt_values.txt
     *
     * @param string $data little endian array of length AL
     * @param string $sessionKey
     *
     * @return string little endian array of length AL
     */
    public function encrypt(string $data, string $sessionKey): string
    {
        $index = 0;
        $last_value = 0;
        $result = '';
        $sessionKeyLength = strlen($sessionKey);

        for ($i = 0; $i < strlen($data); $i++)
        {
            $unencrypted     = gmp_import($data[$i], 1, GMP_LSW_FIRST);
            $sessionKeyValue = gmp_import($sessionKey[$index], 1, GMP_LSW_FIRST);

            $encrypted = ($unencrypted ^ $sessionKeyValue) + $last_value;

            $index = ($index + 1) % $sessionKeyLength;
            $last_value = $encrypted;

            $result .= chr(gmp_intval($encrypted));
        }

        return $result;
    }

    /**
     * [x] = (E - L) ^ S
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/encryption/calculate_decrypt_values.txt
     *
     * @param string $data
     * @param string $sessionKey
     *
     * @return string
     */
    public function decrypt(string $data, string $sessionKey): string
    {
        $index = 0;
        $last_value = 0;
        $result = '';
        $sessionKeyLength = strlen($sessionKey);

        for ($i = 0; $i < strlen($data); $i++)
        {
            $encrypted       = gmp_import($data[$i], 1, GMP_LSW_FIRST);
            $sessionKeyValue = gmp_import($sessionKey[$index], 1, GMP_LSW_FIRST);

            $unencrypted = ($encrypted - $last_value) ^ $sessionKeyValue;

            $index = ($index + 1) % $sessionKeyLength;
            $last_value = $encrypted;

            $result .= chr(gmp_intval($unencrypted));
        }

        return $result;
    }

    /**
     * sha1( username | 0 | client_seed | server_seed | session_key )
     *
     * @link https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/verification_values/encryption/calculate_world_server_proof.txt
     *
     * @param string $username
     * @param string $clientSeed
     * @param string $serverSeed
     * @param string $sessionKey
     *
     * @return string
     */
    public function calculate_world_server_proof(string $username, string $clientSeed, string $serverSeed, string $sessionKey): string
    {
        $zero = "\x00\x00\x00\x00";

        return $this->hash($username . $zero .  $clientSeed . $serverSeed . strrev($sessionKey), true);
    }

    /**
     * @param string $string
     * @param bool $binary
     *
     * @return string
     */
    private function hash(string $string, bool $binary = false): string
    {
        return hash($this->hasher, $string, $binary);
    }
}