//
//  ECDHUtils.h
//

#import <Foundation/Foundation.h>
#import <CommonCrypto/CommonCryptor.h>
#include <openssl/evp.h>
#include <openssl/ecdh.h>

#define SHA_DIGEST_LENGTH 256
#define KEY_LENGTH 32

@interface ECDHUtils : NSObject

-(EC_POINT*)generatePublicKey:(NSString*)publicKey_x_str
                  publicKey_y:(NSString*)publicKey_y_str;
-(EC_POINT*)generatePublicKey:(NSString*)publicKey_str;

-(void)calculateSymmetricKey:(NSString*)other_publicKey_x
           other_publicKey_y:(NSString*)other_publicKey_y;
-(void)calculateSymmetricKey:(NSString*)other_publicKey;


@property EC_KEY   *key_curve;
@property NSString *PrivatKey;
@property NSString *PublicKey;
@property EC_POINT *PublicKeyPoint;
@property NSString *PublicKeyX;
@property NSString *PublicKeyY;
@property NSString *SymmetricKey;

@end
