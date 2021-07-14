# Copyright (c) 2014-present, The osquery authors
#
# This source code is licensed as defined by the LICENSE file found in the
# root directory of this source tree.
#
# SPDX-License-Identifier: (Apache-2.0 OR GPL-2.0-only)

function(mbedtls)
  set(library_root "${CMAKE_CURRENT_SOURCE_DIR}/src")
  add_library(thirdparty_mbedtls
    "${library_root}/library/aes.c"
    "${library_root}/library/aesni.c"
    "${library_root}/library/arc4.c"
    "${library_root}/library/aria.c"
    "${library_root}/library/asn1parse.c"
    "${library_root}/library/asn1write.c"
    "${library_root}/library/base64.c"
    "${library_root}/library/bignum.c"
    "${library_root}/library/blowfish.c"
    "${library_root}/library/camellia.c"
    "${library_root}/library/ccm.c"
    "${library_root}/library/chacha20.c"
    "${library_root}/library/chachapoly.c"
    "${library_root}/library/cipher.c"
    "${library_root}/library/cipher_wrap.c"
    "${library_root}/library/cmac.c"
    "${library_root}/library/ctr_drbg.c"
    "${library_root}/library/des.c"
    "${library_root}/library/dhm.c"
    "${library_root}/library/ecdh.c"
    "${library_root}/library/ecdsa.c"
    "${library_root}/library/ecjpake.c"
    "${library_root}/library/ecp.c"
    "${library_root}/library/ecp_curves.c"
    "${library_root}/library/entropy.c"
    "${library_root}/library/entropy_poll.c"
    "${library_root}/library/error.c"
    "${library_root}/library/gcm.c"
    "${library_root}/library/havege.c"
    "${library_root}/library/hkdf.c"
    "${library_root}/library/hmac_drbg.c"
    "${library_root}/library/md.c"
    "${library_root}/library/md2.c"
    "${library_root}/library/md4.c"
    "${library_root}/library/md5.c"
    "${library_root}/library/memory_buffer_alloc.c"
    "${library_root}/library/nist_kw.c"
    "${library_root}/library/oid.c"
    "${library_root}/library/padlock.c"
    "${library_root}/library/pem.c"
    "${library_root}/library/pk.c"
    "${library_root}/library/pk_wrap.c"
    "${library_root}/library/pkcs12.c"
    "${library_root}/library/pkcs5.c"
    "${library_root}/library/pkparse.c"
    "${library_root}/library/pkwrite.c"
    "${library_root}/library/platform.c"
    "${library_root}/library/platform_util.c"
    "${library_root}/library/poly1305.c"
    "${library_root}/library/psa_crypto.c"
    "${library_root}/library/psa_crypto_driver_wrappers.c"
    "${library_root}/library/psa_crypto_se.c"
    "${library_root}/library/psa_crypto_slot_management.c"
    "${library_root}/library/psa_crypto_storage.c"
    "${library_root}/library/psa_its_file.c"
    "${library_root}/library/ripemd160.c"
    "${library_root}/library/rsa.c"
    "${library_root}/library/rsa_internal.c"
    "${library_root}/library/sha1.c"
    "${library_root}/library/sha256.c"
    "${library_root}/library/sha512.c"
    "${library_root}/library/threading.c"
    "${library_root}/library/timing.c"
    "${library_root}/library/version.c"
    "${library_root}/library/version_features.c"
    "${library_root}/library/xtea.c"
    "${library_root}/library/certs.c"
    "${library_root}/library/pkcs11.c"
    "${library_root}/library/x509.c"
    "${library_root}/library/x509_create.c"
    "${library_root}/library/x509_crl.c"
    "${library_root}/library/x509_crt.c"
    "${library_root}/library/x509_csr.c"
    "${library_root}/library/x509write_crt.c"
    "${library_root}/library/x509write_csr.c"
    "${library_root}/library/debug.c"
    "${library_root}/library/net_sockets.c"
    "${library_root}/library/ssl_cache.c"
    "${library_root}/library/ssl_ciphersuites.c"
    "${library_root}/library/ssl_cli.c"
    "${library_root}/library/ssl_cookie.c"
    "${library_root}/library/ssl_msg.c"
    "${library_root}/library/ssl_srv.c"
    "${library_root}/library/ssl_ticket.c"
    "${library_root}/library/ssl_tls.c"
    "${library_root}/library/ssl_tls13_keys.c"
    )
  target_include_directories(thirdparty_mbedtls PUBLIC
    "${library_root}/include"
    )

target_compile_definitions(thirdparty_mbedtls PRIVATE MBEDTLS_MD2_C MBEDTLS_MD4_C MBEDTLS_PEM_PARSE_C
                MBEDTLS_X509_CRT_PARSE_C MBEDTLS_PEM_WRITE_C
                MBEDTLS_PKCS1_V15 MBEDTLS_PKCS1_V21
                MBEDTLS_X509_ALLOW_UNSUPPORTED_CRITICAL_EXTENSION
		)
target_link_libraries(thirdparty_mbedtls PRIVATE
  thirdparty_c_settings
  )
	      
endfunction()

mbedtls()
