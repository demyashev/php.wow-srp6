# WoW SRP6

A PHP library for generating authorization keys and encrypting data for World of Warcraft.

It can be used to register a client in the database, connect to the server, and send/receive encrypted data packets.
# Usage

A step-by-step usage example. For a local CMaNGOS server, simply generate `$s` and `$v` and write them to the corresponding fields in the `wotlkrealmd.account` table.
```php
require 'vendor/autoload.php';

$username = 'username123';
$password = 'password123';

$srp = new \WOWSRP\SRP();

# salt (wotlkrealmd.account.s)
$s = random_bytes(32);

# password verified (wotlkrealmd.account.v)
$v = $srp->calculate_password_verifier($username, $password, $s);

# server private and public keys
$b = random_bytes(32);
$B = $srp->calculate_server_public_key($v, $b);

# client private and public keys
$a = random_bytes(32);
$A = $srp->calculate_client_public_key($a);

$x = $srp->calculate_x($username, $password, $s);
$u = $srp->calculate_u($A, $B);
$c_S = $srp->calculate_client_s_key($a, $B, $x, $u);
$c_K = $srp->calculate_interleaved($c_S);

# client proof
$c_M1 = $srp->calculate_client_proof($username, $c_K, $A, $B, $s);

$s_S = $srp->calculate_server_s_key($A, $v, $u, $b);
$s_K = $srp->calculate_interleaved($s_S);
$s_M1 = $srp->calculate_client_proof($username, $s_K, $A, $B, $s);

# authenticated
assert($c_M1 === $s_M1);

# server proof
$s_M2 = $srp->calculate_server_proof($A, $s_M1, $s_K);
```

# Tests

Testing was performed on [CMaNGOS](https://github.com/cmangos/mangos-wotlk) (mangos-wotlk) Development Build (2025-11-25).

PHPUnit tests are also available. Test data was taken [here](https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/#constants).

```shell
php composer test
```

# Documentation

Useful links on the basis of which this library was written:
- [Implementation Guide for the World of Warcraft flavor of SRP6](https://gtker.com/implementation-guide-for-the-world-of-warcraft-flavor-of-srp6/) — You can also find implementations of this library in other languages there.
- [CMaNGOS Authorization Source Code in C++](https://github.com/cmangos/mangos-wotlk/blob/master/src/realmd/AuthSocket.cpp)

# License

All files are covered by the MIT license