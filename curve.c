#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"
#include "php_curve25519.h"
#include "ext/standard/info.h"
#include "zend_exceptions.h"
#include "ext/spl/spl_exceptions.h"

const unsigned char basepoint[32] = {9};

void curve25519_clamp(unsigned char secret[32])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

PHP_FUNCTION(curve25519_sign)
{
    char *random;
    char *privatekey;
    char *message;

#if PHP_VERSION_ID >= 70000
    size_t random_len;
    size_t private_len;
    size_t message_len;
#else
    int random_len;
    int private_len;
    int message_len;
#endif 

    char signature[64];

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &random, &random_len, &privatekey, &private_len, &message, &message_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(random, random_len)
        Z_PARAM_STRING(privatekey, private_len)
        Z_PARAM_STRING(message, message_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

    if (private_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Private key must be 32 bytes", 0 TSRMLS_CC);
    }

    if (random_len != 64) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Random must be 64-byte string", 0 TSRMLS_CC);
    }

 	curve25519_sign((unsigned char *)signature, (unsigned char *)privatekey, 
                    (unsigned char *)message, message_len, (unsigned char *)random);

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL((char*)signature, 64);
#else
    RETURN_STRINGL((char*)signature, 64, 1);
#endif  
}

PHP_FUNCTION(curve25519_verify)
{
    char *publickey;
    char *message;
    char *signature;

#if PHP_VERSION_ID >= 70000
    size_t public_len;
    size_t message_len;
    size_t signature_len;
#else
    unsigned int public_len;
    unsigned int message_len;
    unsigned int signature_len;
#endif  

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &publickey, &public_len, &message, &message_len, &signature, &signature_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(3, 3)
        Z_PARAM_STRING(publickey, public_len)
        Z_PARAM_STRING(message, message_len)
        Z_PARAM_STRING(signature, signature_len)   
    ZEND_PARSE_PARAMETERS_END();
#endif

    if (public_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Public must be 32 bytes", 0 TSRMLS_CC);
    }

    if (signature_len != 64) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Signature must be 64-byte string", 0 TSRMLS_CC);
    }

    int result = curve25519_verify((unsigned char *)signature, (unsigned char *)publickey, 
                                   (unsigned char *)message, message_len);
    RETURN_LONG(result);
}

PHP_FUNCTION(curve25519_private)
{
	char *random;

#if PHP_VERSION_ID >= 70000
    size_t random_len;
#else
    int random_len;
#endif  

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &random, &random_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(random, random_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

	if (random_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Random must be 32-byte string", 0 TSRMLS_CC);
    }

	random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL(random, 32);
#else
    RETURN_STRINGL(random, 32, 1);
#endif  
}

PHP_FUNCTION(curve25519_public)
{
	char *private;
#if PHP_VERSION_ID >= 70000
    size_t private_len;
#else
    int private_len;
#endif 

    char basepoint[32] = {9};

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &private, &private_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(1, 1)
        Z_PARAM_STRING(private, private_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

	if (private_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Private key must be 32 bytes", 0 TSRMLS_CC);
    }

	char public[32];
	curve25519_donna(public, private, basepoint);

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL((char*)public, 32);
#else
    RETURN_STRINGL((char*)public, 32, 1);
#endif  
}

PHP_FUNCTION(curve25519_shared)
{
    char *private;
    char *public;

#if PHP_VERSION_ID >= 70000
    size_t private_len;
    size_t public_len;
#else
    int private_len;
    int public_len;
#endif 

#ifndef FAST_ZPP
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &private, &private_len, &public, &public_len) == FAILURE) {
        RETURN_FALSE;
    }
#else
    ZEND_PARSE_PARAMETERS_START(2, 2)
        Z_PARAM_STRING(private, private_len)
        Z_PARAM_STRING(public, public_len)
    ZEND_PARSE_PARAMETERS_END();
#endif

	if (private_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Private key must be 32 bytes", 0 TSRMLS_CC);
    }

	if (public_len != 32) {
        zend_throw_exception(spl_ce_InvalidArgumentException, "Public must be 32 bytes", 0 TSRMLS_CC);
    }

	char shared_key[32];
	curve25519_donna(shared_key, private, public);

#if PHP_VERSION_ID >= 70000
    RETURN_STRINGL(shared_key, 32);
#else
    RETURN_STRINGL(shared_key, 32, 1);
#endif  
}

ZEND_BEGIN_ARG_INFO_EX(arginfo_curve25519_sign, 0, 0, 1)
	ZEND_ARG_INFO(0, random)
	ZEND_ARG_INFO(0, private)
	ZEND_ARG_INFO(0, message)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_curve25519_verify, 0, 0, 1)
	ZEND_ARG_INFO(0, public)
	ZEND_ARG_INFO(0, message)
	ZEND_ARG_INFO(0, signature)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_curve25519_private, 0, 0, 1)
	ZEND_ARG_INFO(0, random)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_curve25519_public, 0, 0, 1)
	ZEND_ARG_INFO(0, secret)
ZEND_END_ARG_INFO()

ZEND_BEGIN_ARG_INFO_EX(arginfo_curve25519_shared, 0, 0, 1)
	ZEND_ARG_INFO(0, secret)
	ZEND_ARG_INFO(0, public)
ZEND_END_ARG_INFO()

const zend_function_entry curve25519_functions[] = {
	PHP_FE(curve25519_public, arginfo_curve25519_public)
	PHP_FE(curve25519_shared, arginfo_curve25519_shared)
	PHP_FE(curve25519_private, arginfo_curve25519_private)
	PHP_FE(curve25519_sign, arginfo_curve25519_sign)
	PHP_FE(curve25519_verify, arginfo_curve25519_verify)
	PHP_FE_END
};

PHP_MINFO_FUNCTION(curve25519)
{
	php_info_print_table_start();
	php_info_print_table_row(2, "curve25519 support", "enabled");
	php_info_print_table_end();
}

zend_module_entry curve25519_module_entry = {
	STANDARD_MODULE_HEADER,
	"curve25519",
	curve25519_functions,
	NULL,
	NULL,
	NULL,
	NULL,
	PHP_MINFO(curve25519),
	NO_VERSION_YET,
	STANDARD_MODULE_PROPERTIES
};

#ifdef COMPILE_DL_CURVE25519
ZEND_GET_MODULE(curve25519)
#endif
