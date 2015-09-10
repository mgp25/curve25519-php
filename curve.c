#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "php.h"

const unsigned char basepoint[32] = {9};

void curve25519_clamp(unsigned char secret[32])
{
	secret[0] &= 248;
	secret[31] &= 127;
	secret[31] |= 64;
}

PHP_FUNCTION(curve25519_sign){
    unsigned char *random;
    int random_len;
    unsigned char *privatekey;
    int private_len;
    unsigned char *message;
    int message_len;
    char signature[64];
	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &random, &random_len,&privatekey,&private_len,&message,&message_len) == FAILURE) {
		RETURN_FALSE;
	}
	if (private_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Private must be 32 bytes");
		RETURN_FALSE
	}
    if (random_len != 64) {
        php_error_docref(NULL TSRMLS_CC,E_WARNING, "Random must be 64-byte string");
        RETURN_FALSE
    }
 	curve25519_sign((unsigned char *)signature, (unsigned char *)privatekey, 
                    (unsigned char *)message, message_len, (unsigned char *)random);
 	RETURN_STRING(signature, 64);
}
PHP_FUNCTION(curve25519_verify){
	unsigned char *publickey;
	int public_len;
    unsigned char *message;
    int message_len;
    unsigned char *signature;
    int signature_len;
    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "sss", &publickey, &public_len,&message,&message_len,&signature,&signature_len) == FAILURE) {
		RETURN_FALSE;
	}	
	if (public_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Public must be 32 bytes");
		RETURN_FALSE
	}
    if (signature_len != 64) {
        php_error_docref(NULL TSRMLS_CC,E_WARNING, "Signature must be 64-byte string");
        RETURN_FALSE
    }
    int result = curve25519_verify((unsigned char *)signature, (unsigned char *)publickey, 
                                   (unsigned char *)message, message_len);
    RETURN_LONG(result);
}
PHP_FUNCTION(curve25519_private){
	unsigned char *random;
	int random_len;

    if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &random, &random_len) == FAILURE) {
		RETURN_FALSE;
	}	
	if (random_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Random must be 32 bytes");
		RETURN_FALSE
	}
	random[0] &= 248;
    random[31] &= 127;
    random[31] |= 64;

    RETURN_STRINGL(random, 32, 1);
}
PHP_FUNCTION(curve25519_public)
{
	unsigned char *private;
	int private_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "s", &private, &private_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (private_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Private must be 32 bytes");
		RETURN_FALSE
	}

	char *dup = estrdup(private);
	unsigned char public[32];
	curve25519_donna(public, dup, basepoint);

	efree(dup);

	RETURN_STRINGL(public, 32, 1);
}

PHP_FUNCTION(curve25519_shared)
{
	unsigned char *private;
	int private_len;

	unsigned char *public;
	int public_len;


	if (zend_parse_parameters(ZEND_NUM_ARGS() TSRMLS_CC, "ss", &private, &private_len, &public, &public_len) == FAILURE) {
		RETURN_FALSE;
	}

	if (private_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Private must be 32 bytes");
		RETURN_FALSE;
	}

	if (public_len != 32) {
		php_error_docref(NULL TSRMLS_CC, E_WARNING, "Public must be 32 bytes");
		RETURN_FALSE;
	}
	char *dup = estrdup(private);
	unsigned char shared_key[32];
	curve25519_donna(shared_key, dup, public);
	efree(dup);
	RETURN_STRINGL(shared_key, 32, 1);
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