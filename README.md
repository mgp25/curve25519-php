# Curve25519 extension for PHP

![php](https://img.shields.io/badge/php-%3E%3D%207.0-blue.svg) [![sponsor](https://img.shields.io/badge/-Become%20a%20sponsor%20❤-ff6964)](https://github.com/sponsors/mgp25)

Curve25519 library with Ed25519 signatures extension for PHP. It supports PHP 8.

## Usage

```php
$randomBytes = random_bytes(32);
$private = curve25519_private($randomBytes);
$public  = curve25519_public($private);
        
$agreement = curve25519_shared($private, $public);
$signature = curve25519_sign(random_bytes(64), $private, $message);
$verified  = curve25519_verify($public, $message, $signature) == 0;
```

If you are using it in combination with [LibSignal for PHP](https://github.com/mgp25/libsignal-php):

```php
$randomBytes = random_bytes(32);
$private = curve25519_private($randomBytes);
$public  = curve25519_public($private);
$keyPair = new ECKeyPair(new DjbECPublicKey($public), new DjbECPrivateKey($private));
        
$agreement = curve25519_shared($keyPair->getPrivateKey(), $keyPair->getPublicKey());
$signature = curve25519_sign(random_bytes(64), $signingKey->getPrivateKey(), $message);
$verified  = curve25519_verify($signingKey->getPublicKey(), $message, $signature) == 0;
```

# Installation
## Linux and MacOS

```
phpize
./configure
make
sudo make install
```

When installed, make sure to add it in your `php.ini` env:

```
php --ini # will reveal your .ini path
# Edit the file and add:
extension=curve25519
```
