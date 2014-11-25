//
//  StampCrypto.m
//  app-crypto
//
//  Created by Mathias Kaufmann on 24.11.14.
//  Copyright (c) 2014 Mathias Kaufmann. All rights reserved.
//

#import "StampCrypto.h"

@implementation StampCrypto


-(id)init
{
    [self setBits:@4096];
    [self setServer:[NSURL URLWithString:@"http://localhost:3000/"]];
    return self;
}

- (int)registerDeviceAndSignRequest
{
    
    NSString *delete_url = [NSString stringWithFormat:@"%@devices/%@",[self server],[self udid]];
    NSString *create_url = [NSString stringWithFormat:@"%@devices",[self server]];
    NSDictionary *device = @{
                             @"id":[self udid],
                             @"certificate_signing_request":[self requestPem],
                             };
    NSDictionary *parameters = @{@"device":device};
    AFHTTPRequestOperationManager *manager = [AFHTTPRequestOperationManager manager];
    [manager.requestSerializer setValue:@"application/json" forHTTPHeaderField:@"Accept"];
    [manager.requestSerializer setValue:@"application/x-www-form-urlencoded" forHTTPHeaderField:@"Content-Type"];
    [manager DELETE:delete_url parameters:nil success:^(AFHTTPRequestOperation *operation, id responseObject) {
        NSLog(@"Device deleted");
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        NSLog(@"An error occurred during deletion");
    }];
    [manager POST:create_url parameters:parameters success:^(AFHTTPRequestOperation *operation, id responseObject) {
        self.device = (NSDictionary *)responseObject;
        self.title = @"JSON Retrieved";
    } failure:^(AFHTTPRequestOperation *operation, NSError *error) {
        NSLog(@"An error occurred");
    }];
    return 1;
}

-(int)add_ext:(int)nid value:(char*)value
{
    X509_EXTENSION *ex;
    ex = X509V3_EXT_conf_nid(NULL, NULL, nid, value);
    if (!ex)
        return 0;
    sk_X509_EXTENSION_push([self exts], ex);
    
    return 1;
}

-(int)makeRequest
{
    NSString *reqPem;
    NSString *keyPem;
    [self setUdid: [UIDevice currentDevice].identifierForVendor.UUIDString];
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);
    BIO *bio_err=BIO_new_fp(stderr, BIO_NOCLOSE);
    EVP_PKEY *pk;
    RSA *rsa;
    
    if ((pk=EVP_PKEY_new()) == NULL)
        goto err_csr;
    
    rsa=RSA_generate_key([[self bits] intValue],RSA_F4,NULL,NULL);
    if (!EVP_PKEY_assign_RSA(pk,rsa))
        goto err_csr;
    
    rsa=NULL;
    
    [self setPrivateKey:pk];

    X509_NAME *name=NULL;
    [self setExts:sk_X509_EXTENSION_new_null()];
    
    [self setRequest:X509_REQ_new()];
    if ([self request] == NULL)
        goto err_csr;
    
    X509_REQ_set_pubkey([self request],[self privateKey]);
    
    name=X509_REQ_get_subject_name([self request]);
    
    /* This function creates and adds the entry, working out the
     * correct string type and performing checks on its length.
     * Normally we'd check the return value for errors...
     */
    
    const unsigned char country[] = "DE";
    const unsigned char state[] = "Sachsen";
    const unsigned char location[] = "Dresden";
    const unsigned char organization[] = "ASCII Dresden";
    const unsigned char organizational_unit[] = "Stamp Signing";
    const unsigned char* common_name = (unsigned char*) [[self udid] cStringUsingEncoding:NSUTF8StringEncoding];
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

    
    [self add_ext:NID_key_usage value:"critical,digitalSignature,keyEncipherment"];
    
    [self add_ext:NID_subject_alt_name value:"email:steve@openssl.org"];
    
    [self add_ext:NID_netscape_cert_type value:"client"];
    
    X509_REQ_add_extensions([self request], [self exts]);
    
    sk_X509_EXTENSION_pop_free([self exts], X509_EXTENSION_free);
    
    if (!X509_REQ_sign([self request],[self privateKey],EVP_sha512()))
        goto err_csr;
    
    BIO *key = BIO_new(BIO_s_mem());
    BIO *request = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_PrivateKey(key, [self privateKey], NULL, NULL, 0, 0, NULL))
        goto err_csr;

    if (!PEM_write_bio_X509_REQ(request, [self request]))
        goto err_csr;

    const void* key_pem = malloc(key->num_write+1);
    const void* request_pem = malloc(request->num_write+1);
    
    long reqSize = BIO_get_mem_data(request,&request_pem);
    long keySize = BIO_get_mem_data(key,&key_pem);

    reqPem = [[NSString alloc] initWithBytes:request_pem
                                      length:reqSize
                                    encoding:NSASCIIStringEncoding];
    keyPem = [[NSString alloc] initWithBytes:key_pem
                                      length:keySize
                                    encoding:NSASCIIStringEncoding];
    [self setPrivateKeyPem:keyPem];
    [self setRequestPem:reqPem];
    X509_REQ_free([self request]);
    EVP_PKEY_free([self privateKey]);
    
#ifndef OPENSSL_NO_ENGINE
    ENGINE_cleanup();
#endif
    CRYPTO_cleanup_all_ex_data();
    
    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);
    return(0);
err_csr:
    return(1);
}

@end
