//
//  StampCrypto.h
//  app-crypto
//
//  Created by Mathias Kaufmann on 24.11.14.
//  Copyright (c) 2014 Mathias Kaufmann. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <UIKit/UIKit.h>

#import <stdio.h>
#import <stdlib.h>

#import <openssl/pem.h>
#import <openssl/conf.h>
#import <openssl/x509v3.h>
#import <openssl/engine.h>

#import <openssl/pkcs12.h>
#import <openssl/err.h>

#import <AFNetworking/AFHTTPRequestOperation.h>
#import <AFNetworking/AFHTTPRequestOperationManager.h>

@interface StampCrypto : NSObject

@property X509_REQ *request;
@property EVP_PKEY *privateKey;
@property NSString *requestPem;
@property NSString *privateKeyPem;
@property NSURL *server;
@property NSString *udid;
@property NSDictionary *device;
@property NSString *title;

@property NSNumber *bits;
@property STACK_OF(X509_EXTENSION) *exts;

- (int)makeRequest;

- (int)add_ext:(int)nid value:(char*)value;
- (int)registerDeviceAndSignRequest;
@end
