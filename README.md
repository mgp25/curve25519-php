# curve25519 php

Curve25519 library with Ed25519 signatures extension for PHP. This is used in [Chat API](https://github.com/WHAnonymous/Chat-API)

```php
        $secureRandom = self::getSecureRandom();
        $private = curve25519_private($secureRandom);
        $public = curve25519_public($private);
        $keyPair = new ECKeyPair(new DjbECPublicKey($public),new DjbECPrivateKey($private));
        
        $agreement = curve25519_shared( $keyPair->getPrivateKey(),$keyPair->getPublicKey());
        $signature = curve25519_sign(getSecureRandom(64), $signingKey->getPrivateKey(), $message);
        $verified  = curve25519_verify($signingKey->getPublicKey(), $message, $signature) == 0;
```

# Installation
## Linux and OS X

```
phpize
./configure
make
sudo make install
```

