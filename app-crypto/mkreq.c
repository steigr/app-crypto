//
//  mkreq.c
//  app-crypto
//
//  Created by Mathias Kaufmann on 24.11.14.
//  Copyright (c) 2014 Mathias Kaufmann. All rights reserved.
//

#include "mkreq.h"

int build_req(const char* udid,char* csr_pem)
{
        BIO *bio_err;
        X509_REQ *req=NULL;
        EVP_PKEY *pkey=NULL;
    
        CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
        bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    
        mkreq(udid,csr_pem,&req,&pkey,4096,0,365);
    
        RSA_print_fp(stdout,pkey->pkey.rsa,0);
        X509_REQ_print_fp(stdout,req);
    
        PEM_write_X509_REQ(stdout,req);
    
        X509_REQ_free(req);
        EVP_PKEY_free(pkey);
    
    #ifndef OPENSSL_NO_ENGINE
        ENGINE_cleanup();
    #endif
        CRYPTO_cleanup_all_ex_data();
        
        CRYPTO_mem_leaks(bio_err);
        BIO_free(bio_err);
        return(0);
    
}

/* Add extension using V3 code: we can set the config file as NULL
 * because we wont reference any other sections.
 */

int add_ext(STACK_OF(X509_EXTENSION)* sk, int nid, char* value)
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push(sk, ex);
    
    return 1;
}

int mkkey(void* keyPtr, int bits)
{
//    FILE *fp;
    
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    
    BIO *bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);

    EVP_PKEY *pk;
    RSA *rsa;
    
    if ((pk=EVP_PKEY_new()) == NULL)
        goto err_key;
    
    rsa=RSA_generate_key(bits,RSA_F4,NULL,NULL);
    if (!EVP_PKEY_assign_RSA(pk,rsa))
        goto err_key;
    
    rsa=NULL;

    BIO *pem = BIO_new(BIO_s_mem());
    

    if (!PEM_write_bio_PrivateKey(pem, pk, NULL, NULL, 0, 0, NULL))
        goto err_key;
    
    void* key_pem = malloc(pem->num_write+1);

    BIO_get_mem_data(pem,&key_pem);

    printf("%s",key_pem);
    EVP_PKEY_free(pk);
    
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();
    
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    keyPtr = malloc(strlen(key_pem));
    strcpy(key_pem,keyPtr);
    return(0);
err_key:
    return(1);

}

int mkreq(const char* udid, char* req_pem, X509_REQ **req, EVP_PKEY **pkeyp, int bits, int serial, int days)
{
    X509_REQ *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *name=NULL;
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null(); //NULL;
    
    if ((pk=EVP_PKEY_new()) == NULL)
        goto err;
    
    if ((x=X509_REQ_new()) == NULL)
        goto err;
    
    rsa=RSA_generate_key(bits,RSA_F4,NULL,NULL);
    if (!EVP_PKEY_assign_RSA(pk,rsa))
        goto err;
    
    rsa=NULL;
    
    X509_REQ_set_pubkey(x,pk);
    
    name=X509_REQ_get_subject_name(x);
    
    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */

    const unsigned char country[] = "DE";
    const unsigned char state[] = "Sachsen";
    const unsigned char location[] = "Dresden";
    const unsigned char organization[] = "ASCII Dresden";
    const unsigned char organizational_unit[] = "Stamp Signing";
    const unsigned char* common_name = (unsigned char*) udid;
    X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC, country, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"ST",
                               MBSTRING_ASC, state, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"L",
                               MBSTRING_ASC, location, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"O",
                               MBSTRING_ASC, organization, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"OU",
                               MBSTRING_ASC, organizational_unit, -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, common_name, -1, -1, 0);
    
    
    add_ext(exts, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    
    /* This is a typical use for request extensions: requesting a value for
     * subject alternative name.
     */
    
    add_ext(exts, NID_subject_alt_name, "email:steve@openssl.org");
    
    /* Some Netscape specific extensions */
    add_ext(exts, NID_netscape_cert_type, "client");
    
    
    
//#ifdef CUSTOM_EXT
//    /* Maybe even add our own extension based on existing */
//    {
//        int nid;
//        nid = OBJ_create("1.2.3.4", "MyAlias", "My Test Alias Extension");
//        X509V3_EXT_add_alias(nid, NID_netscape_comment);
//        add_ext(x, nid, "example comment alias");
//    }
//#endif
//    
    /* Now we've created the extensions we add them to the request */
    
    X509_REQ_add_extensions(x, exts);
    
    sk_X509_EXTENSION_pop_free(exts, X509_EXTENSION_free);
    
//#endif
    
    if (!X509_REQ_sign(x,pk,EVP_sha1()))
        goto err;
    
    *req=x;
    *pkeyp=pk;
    return(1);
err:
    return(0);
}

