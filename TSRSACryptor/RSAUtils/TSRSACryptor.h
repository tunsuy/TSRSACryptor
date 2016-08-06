//
//  TSRSACryptor.h
//  TSRSACryptor
//
//  Created by tunsuy on 1/7/16.
//  Copyright © 2016年 tunsuy. All rights reserved.
//

#import <Foundation/Foundation.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>

typedef NS_ENUM(NSInteger, RSA_PADDING_TYPE) {
    RSA_PADDING_TYPE_NONE   = RSA_NO_PADDING,
    RSA_PADDING_TYPE_PKCS1  = RSA_PKCS1_PADDING,
    RSA_PADDING_TYPE_SSLV23 = RSA_SSLV23_PADDING
};

typedef NS_ENUM(int, RSA_SIGN_DIGEST_TYPE) {
    RSA_SIGN_DIGEST_TYPE_sha1   = NID_sha1,
    RSA_SIGN_DIGEST_TYPE_sha256 = NID_sha256,
    RSA_SIGN_DIGEST_TYPE_sha512 = NID_sha512,
    RSA_SIGN_DIGEST_TYPE_md5    = NID_md5
};

@interface TSRSACryptor : NSObject
{
    RSA *_rsaPublic;
    RSA *_rsaPrivate;
    
    RSA *_rsa;
}
@end
