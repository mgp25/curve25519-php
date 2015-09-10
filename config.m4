PHP_ARG_ENABLE(curve25519, whether to enable cuve25519 extension,
[ --enable-curve25519   Enable "php-curve25519" extension support])
 
if test $PHP_CURVE25519 != "no"; then
  AC_DEFINE(HAVE_CURVE25519, 1, [Whether you have curve25519 extension])
  PHP_NEW_EXTENSION(curve25519, curve.c curve/curve25519-donna.c curve/ed25519/*.c curve/ed25519/additions/*.c curve/ed25519/nacl_sha512/*.c, $ext_shared)
fi

