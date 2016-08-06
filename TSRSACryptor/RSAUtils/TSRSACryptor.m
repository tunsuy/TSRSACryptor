//
//  TSRSACryptor.m
//  TSRSACryptor
//
//  Created by tunsuy on 1/7/16.
//  Copyright © 2016年 tunsuy. All rights reserved.
//

#import "TSRSACryptor.h"
#import <CommonCrypto/CommonCrypto.h>

typedef NS_ENUM(NSInteger, RSAKeyType) {
    RSAKeyTypePublic = 0,
    RSAKeyTypePrivate
};

#define DocumentsDir [NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES) lastObject]
#define OpenSSLRSAKeyDir [DocumentsDir stringByAppendingPathComponent:@".openssl_rsa"]
#define OpenSSLRSAPublicKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.publicKey.pem"]
#define OpenSSLRSAPrivateKeyFile [OpenSSLRSAKeyDir stringByAppendingPathComponent:@"bb.privateKey.pem"]

@implementation TSRSACryptor

- (BOOL)generateRSAKeyPairWithKeySize:(int)keySize {
    if (_rsa != NULL) {
        RSA_free(_rsa);
        _rsa = NULL;
    }
    
    _rsa = RSA_generate_key(keySize, RSA_F4, NULL, NULL);
    assert(_rsa != NULL);
    
    const char *publicKeyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    const char *privateKeyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
    
    RSA_blinding_on(_rsa, NULL);
    
    BIO *publicBIO = BIO_new_file(publicKeyFileName, "w");
    PEM_write_bio_RSA_PUBKEY(publicBIO, _rsa);
    
    BIO *privateBIO = BIO_new_file(privateKeyFileName, "w");
    PEM_write_bio_RSAPrivateKey(privateBIO, _rsa, NULL, NULL, 0, NULL, NULL);
    
    BIO_free(publicBIO);
    BIO_free(privateBIO);
    
    _rsaPublic = RSAPublicKey_dup(_rsa);
    assert(_rsaPublic != NULL);
    _rsaPrivate = RSAPublicKey_dup(_rsa);
    assert(_rsaPrivate != NULL);
    
    if (_rsa && _rsaPrivate && _rsaPublic) {
        return YES;
    }
    return NO;
}

#pragma mark - 导入pem文件data
- (RSA *)rsaWithKeyType:(RSAKeyType)keyType pemData:(NSData *)pemData {
    const void *bytes = [pemData bytes];
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)pemData.length);
    
    RSA *rsa = NULL;
    switch (keyType) {
        case RSAKeyTypePublic:
            rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
            break;
        case RSAKeyTypePrivate:
            rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
            break;
            
        default:
            break;
    }
    
    assert(rsa != NULL);
    BIO_free_all(bio);
    
    return rsa;
}

- (BOOL)importRSAPublicKeyWithPemData:(NSData *)pemData {
    _rsaPublic = [self rsaWithKeyType:RSAKeyTypePublic pemData:pemData];
    return _rsaPublic ? YES : NO;
}

- (BOOL)importRSAPrivateKeyWithPemData:(NSData *)pemData {
    _rsaPrivate = [self rsaWithKeyType:RSAKeyTypePrivate pemData:pemData];
    return _rsaPrivate ? YES : NO;
}

#pragma mark - 导入der格式data
- (RSA *)rsaWithKeyType:(RSAKeyType)keyType derData:(NSData *)derData {
    const void *bytes = [derData bytes];
    BIO *bio = BIO_new_mem_buf((void *)bytes, (int)derData.length);
    
    RSA *rsa = NULL;
    switch (keyType) {
        case RSAKeyTypePublic:
            rsa = d2i_RSA_PUBKEY_bio(bio, NULL);
            break;
        case RSAKeyTypePrivate:
            rsa = d2i_RSAPrivateKey_bio(bio, NULL);
            break;
            
        default:
            break;
    }

    assert(rsa != NULL);
    BIO_free_all(bio);

    return rsa;
}

- (BOOL)importRSAPublicKeyWithDerData:(NSData *)derData {
    _rsaPublic = [self rsaWithKeyType:RSAKeyTypePublic derData:derData];
    return _rsaPublic ? YES : NO;
}

- (BOOL)importRSAPrivateKeyWithDerData:(NSData *)derData {
    _rsaPrivate = [self rsaWithKeyType:RSAKeyTypePrivate derData:derData];
    return _rsaPrivate ? YES : NO;
}

#pragma mark - 导入Base64编码的key串
- (RSA *)rsaWithKeyType:(RSAKeyType)keyType base64KeyStr:(NSString *)keyStr {
    NSMutableString *result = [NSMutableString string];
    
    switch (keyType) {
        case RSAKeyTypePublic:
            [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
            break;
        case RSAKeyTypePrivate:
            [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
            break;
            
        default:
            break;
    }
    
    int lineCount = 0;
    for (NSUInteger i=0; i<keyStr.length; i++) {
        unichar c = [keyStr characterAtIndex:i];
        
        if (c == '\n' || c == '\r') {
            continue;
        }
        
        [result appendFormat:@"%c", c];
        
        if (++lineCount == 64) {
            [result appendString:@"\n"];
            lineCount = 0;
        }
    }
    
    const char *keyFileName = NULL;
    switch (keyType) {
        case RSAKeyTypePublic:
            [result appendString:@"-----END PUBLIC KEY-----\n"];
            
            [result writeToFile:OpenSSLRSAPublicKeyFile atomically:YES encoding:NSASCIIStringEncoding error:nil];
            keyFileName = [OpenSSLRSAPublicKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
            break;
        case RSAKeyTypePrivate:
            [result appendString:@"-----END RSA PRIVATE KEY-----\n"];
            
            [result writeToFile:OpenSSLRSAPrivateKeyFile atomically:YES encoding:NSASCIIStringEncoding error:nil];
            keyFileName = [OpenSSLRSAPrivateKeyFile cStringUsingEncoding:NSASCIIStringEncoding];
            break;
            
        default:
            break;
    }
    
    RSA *rsa = NULL;
    FILE *keyFile = fopen(keyFileName, "rb");
    if (NULL != keyFile) {
        BIO *bio = BIO_new(BIO_s_file());
        BIO_read_filename(bio, keyFile);
        
        switch (keyType) {
            case RSAKeyTypePublic:
                rsa = PEM_read_bio_RSA_PUBKEY(bio, NULL, NULL, NULL);
                break;
            case RSAKeyTypePrivate:
                rsa = PEM_read_bio_RSAPrivateKey(bio, NULL, NULL, NULL);
                break;
                
            default:
                break;
        }

        assert(rsa != NULL);
        BIO_free_all(bio);
    }
    
    return rsa;

}

- (BOOL)importRSAPublicKeyWithBase64KeyStr:(NSString *)publicKey {
    _rsaPublic = [self rsaWithKeyType:RSAKeyTypePublic base64KeyStr:publicKey];
    return _rsaPublic ? YES : NO;
}

- (BOOL)importRSAPrivateKeyWithBase64KeyStr:(NSString *)privateKey {
    _rsaPrivate = [self rsaWithKeyType:RSAKeyTypePrivate base64KeyStr:privateKey];
    return _rsaPrivate ? YES : NO;
}

#pragma mark - pem格式化串
- (NSString *)pemFormatRSAWithKeyType:(RSAKeyType)keyType {
    BIO *bio = BIO_new(BIO_s_mem());
    
    switch (keyType) {
        case RSAKeyTypePublic:
            PEM_write_bio_RSA_PUBKEY(bio, _rsaPublic);
            break;
        case RSAKeyTypePrivate:
            PEM_write_bio_RSAPrivateKey(bio, _rsaPrivate, NULL, NULL, 0, NULL, NULL);
            break;
            
        default:
            break;
    }
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    BIO_set_close(bio, BIO_NOCLOSE);
    BIO_free(bio);
    
    return [NSString stringWithUTF8String:bptr->data];
}

- (NSString *)pemFormatRSAPublic {
    NSAssert(_rsaPublic != NULL, @"you must import the public key first");
    if (!_rsaPublic) {
        return nil;
    }
    
    return [self pemFormatRSAWithKeyType:RSAKeyTypePublic];
}

- (NSString *)pemFormatRSAPrivate {
    NSAssert(_rsaPrivate != NULL, @"you must import the private key first");
    if (!_rsaPrivate) {
        return nil;
    }
    
    return [self pemFormatRSAWithKeyType:RSAKeyTypePrivate];
}

#pragma mark - Base64编码RSAKey-pem格式
- (NSString *)base64EncodedRSAKeyWithKeyType:(RSAKeyType)keyType {
    NSString *pemContent = nil;
    
    switch (keyType) {
        case RSAKeyTypePublic:
            pemContent = [NSString stringWithContentsOfFile:OpenSSLRSAPublicKeyFile encoding:NSUTF8StringEncoding error:nil];
            break;
        case RSAKeyTypePrivate:
            pemContent = [NSString stringWithContentsOfFile:OpenSSLRSAPrivateKeyFile encoding:NSUTF8StringEncoding error:nil];
            break;
            
        default:
            break;
    }
    
    NSString *keyStr = [[pemContent componentsSeparatedByString:@"-----"] objectAtIndex:2];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    keyStr = [keyStr stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    
    return keyStr;
}

- (NSString *)base64EncodedPublicKey {
    if (![[NSFileManager defaultManager] fileExistsAtPath:OpenSSLRSAPublicKeyFile]) {
        return nil;
    }
    
    return [self base64EncodedRSAKeyWithKeyType:RSAKeyTypePublic];
}

- (NSString *)base64EncodedPrivateKey {
    if (![[NSFileManager defaultManager] fileExistsAtPath:OpenSSLRSAPrivateKeyFile]) {
        return nil;
    }
    
    return [self base64EncodedRSAKeyWithKeyType:RSAKeyTypePrivate];
}

#pragma mark - ======= 加密 =======
- (NSData *)encryptWithKeyType:(RSAKeyType)keyType padding:(RSA_PADDING_TYPE)padding originData:(NSData *)originData {
    if ([originData length] == 0) {
        return nil;
    }
    
    int len = (int)[originData length];
    unsigned char *plainBuffer = (unsigned char *)[originData bytes];
    
    int clen;
    unsigned char *cipherBuffer = NULL;
    switch (keyType) {
        case RSAKeyTypePublic:
            clen = RSA_size(_rsaPublic);
            cipherBuffer = calloc(clen, sizeof(unsigned char));
            RSA_public_encrypt(len,plainBuffer,cipherBuffer, _rsaPublic,  padding);
            break;
        case RSAKeyTypePrivate:
            clen = RSA_size(_rsaPrivate);
            cipherBuffer = calloc(clen, sizeof(unsigned char));
            RSA_private_encrypt(len,plainBuffer,cipherBuffer, _rsaPrivate,  padding);
            break;
            
        default:
            break;
    }
    NSData *cipherData = [[NSData alloc] initWithBytes:cipherBuffer length:clen];
    
    free(cipherBuffer);

    return cipherData;
}

- (NSData *)encryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding originData:(NSData *)originData {
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    return [self encryptWithKeyType:RSAKeyTypePublic padding:padding originData:originData];
}

- (NSData *)encryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding originData:(NSData *)originData {
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    return [self encryptWithKeyType:RSAKeyTypePrivate padding:padding originData:originData];
}

#pragma mark - ======= 解密 =======
- (NSData *)decryptWithKeyType:(RSAKeyType)keyType padding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData {
    if ([cipherData length] == 0) {
        return nil;
    }
    
    int len = (int)[cipherData length];
    unsigned char *cipherBuffer = (unsigned char *)[cipherData bytes];

    int mlen;
    unsigned char * originBuffer = NULL;
    switch (keyType) {
        case RSAKeyTypePublic:
            mlen = RSA_size(_rsaPublic);
            originBuffer = calloc(mlen, sizeof(unsigned char));
            RSA_public_decrypt(len, cipherBuffer, originBuffer, _rsaPublic, padding);
            
            break;
        case RSAKeyTypePrivate:
            mlen = RSA_size(_rsaPrivate);
            originBuffer = calloc(mlen, sizeof(unsigned char));
            RSA_private_decrypt(len, cipherBuffer, originBuffer, _rsaPrivate, padding);
            break;
            
        default:
            break;
    }
    NSData *originData = [[NSData alloc] initWithBytes:originBuffer length:mlen];

    free(originBuffer);

    return originData;
}

- (NSData *)decryptWithPublicKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData {
    NSAssert(_rsaPublic != NULL, @"You should import public key first");
    return [self decryptWithKeyType:RSAKeyTypePublic padding:padding cipherData:cipherData];
}

- (NSData *)decryptWithPrivateKeyUsingPadding:(RSA_PADDING_TYPE)padding cipherData:(NSData *)cipherData {
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    return [self decryptWithKeyType:RSAKeyTypePrivate padding:padding cipherData:cipherData];
}

#pragma mark - ======= 摘要 =======
- (NSData *)digestDataOfOriginData:(NSData *)OriginData signDigestType:(RSA_SIGN_DIGEST_TYPE)type {
    if (!OriginData.length) {
        return nil;
    }

#define digestWithType(type) \
    unsigned char digest[CC_##type##_DIGEST_LENGTH];\
    CC_##type([OriginData bytes], (unsigned int)[OriginData length], digest);\
    NSData *result = [NSData dataWithBytes:digest length:CC_##type##_DIGEST_LENGTH];\
    return result;
    
    switch (type) {
        case RSA_SIGN_DIGEST_TYPE_sha1: {
            digestWithType(SHA1);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_sha256: {
            digestWithType(SHA256);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_sha512: {
            digestWithType(SHA512);
        }
            break;
        case RSA_SIGN_DIGEST_TYPE_md5: {
            digestWithType(MD5);
        }
            break;

        default:
            break;
    }

    return nil;
}

#pragma mark - ======= 签名 =======
- (NSData *)signWithPrivateKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type originData:(NSData *)originData {
    NSAssert(_rsaPrivate != NULL, @"You should import private key first");
    NSData *digestData = [self digestDataOfOriginData:originData signDigestType:type];

    unsigned int len = 0;
    unsigned int signLen = RSA_size(_rsaPrivate);
    unsigned char *sign = malloc(signLen);
    memset(sign, 0, signLen);
    
    int ret = RSA_sign(type, [digestData bytes], (unsigned int)[digestData length], sign, &len, _rsaPrivate);
    if (ret == 1) {
        NSData *data = [NSData dataWithBytes:sign length:len];
        free(sign);
        return data;
    }
    free(sign);

    return nil;
}

#pragma mark - ======= 验签 =======
- (BOOL)verifyWithPublicKeyUsingDigest:(RSA_SIGN_DIGEST_TYPE)type signData:(NSData *)signData originData:(NSData *)originData {
    NSAssert(_rsaPublic != NULL, @"You should import public key first");

    NSData *digestData = [self digestDataOfOriginData:originData signDigestType:type];
    
    int ret = RSA_verify(type, [digestData bytes], (unsigned int)[digestData length], [signData bytes], (unsigned int)[signData length], _rsaPublic);
    if (ret == 1) {
        return YES;
    }

    return NO;
}

@end
