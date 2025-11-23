# WoW SRP6

A library for working with WoW server `realmd` and `world`.

# Usage

```php
require 'vendor/autoload.php';

$username = 'username123';
$password = 'password123';

$srp = new \WOWSRP\SRP();

# salt
$s = random_bytes(32);

# password verified
$v = $srp->calculate_password_verifier($username, $password, $s);

# 2. [LogonChallenge] client -> LS: username

# 3. [LogonChallenge] LS -> client: B, s, N, g
# server private key
$b = random_bytes(32);
# server public key
$B = $srp->calculate_server_public_key($v, $b);

# 4. [LogonProof] client -> LS: A, M1
# client private key
$a = random_bytes(32);

# client public key
$A = $srp->calculate_client_public_key($a);

# client S key
$x = $srp->calculate_x($username, $password, $s);
$u = $srp->calculate_u($A, $B);
$c_S = $srp->calculate_client_S_key($a, $B, $x, $u);

# client session key
$c_K = $srp->calculate_interleaved($c_S);
# client proof
$c_M1 = $srp->calculate_client_proof($username, $c_K, $A, $B, $s);

# 5. [LogonProof] LS -> client: M2
# server S key
$u = $srp->calculate_u($A, $B);
$s_S = $srp->calculate_server_S_key($A, $v, $u, $b);

# server session key
$s_K = $srp->calculate_interleaved($s_S);

# check M
$s_M1 = $srp->calculate_client_proof($username, $s_K, $A, $B, $s);

# authenticated
assert($c_M1 === $s_M1);

# server proof
$s_M2 = $srp->calculate_server_proof($A, $s_M1, $s_K);
```

# PHPUnit tests
```shell
php composer test
```

# Documentation
[Implementation Guide for the World of Warcraft flavor of SRP6](https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/)