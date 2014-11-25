//
//  mkreq.h
//  app-crypto
//
//  Created by Mathias Kaufmann on 24.11.14.
//  Copyright (c) 2014 Mathias Kaufmann. All rights reserved.
//

#ifndef __app_crypto__mkreq__
#define __app_crypto__mkreq__

#include <stdio.h>
#include <stdlib.h>

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/engine.h>
#include <openssl/pkcs12.h>
#include <openssl/err.h>

//int add_ext(STACK_OF(X509_REQUEST)* sk, int nid, char *value);
int mkkey(void* keyPtr, int bits);
int mkreq(const char* udid,char* req_pem, X509_REQ **req, EVP_PKEY **pkeyp, int bits, int serial, int days);
//int mkPkcs12ForSigning(CFDataRef key, int bits,char** subject);

extern int build_req(const char* udid, char* req_pem);

#endif /* defined(__app_crypto__mkreq__) */

/* Certificate request creation. Demonstrates some request related
 * operations.
 */

