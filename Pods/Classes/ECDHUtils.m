//
//  ECDHUtils.m
//

#import "ECDHUtils.h"

@implementation ECDHUtils
{
	BN_CTX*     bn_ctx;
	EC_GROUP*   key_group;
	BIGNUM*     privatKey;
	NSData*     symmetricKey;
	
	BIGNUM   *publicKeyXBN;
	BIGNUM   *publicKeyYBN;
}

-(id)init
{
	self.key_curve = NULL;//EC_KEY
	key_group = NULL;//EC_GROUP
	privatKey = NULL;//BIGNUM
	self.PublicKeyPoint = NULL;//EC_POINT
	
	bn_ctx = BN_CTX_new();
	BN_CTX_start(bn_ctx);
	
	//=======================
	
	privatKey = BN_CTX_get(bn_ctx);
	publicKeyXBN = BN_CTX_get(bn_ctx);
	publicKeyYBN = BN_CTX_get(bn_ctx);
	
	//=======================
	NSException *p = [NSException exceptionWithName:@"" reason:@"" userInfo:nil];
	
	if ((self.key_curve = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1)) == NULL)
	@throw p;
	
	if ((key_group = (EC_GROUP *)EC_KEY_get0_group(self.key_curve)) == NULL)
	@throw p;
	
	if (EC_KEY_generate_key(self.key_curve) != 1)
	@throw p;
	
	if ((self.PublicKeyPoint = (EC_POINT *)EC_KEY_get0_public_key(self.key_curve)) == NULL)
	@throw p;
	
	if (EC_POINT_get_affine_coordinates_GFp(key_group, self.PublicKeyPoint, publicKeyXBN, publicKeyYBN, bn_ctx) != 1)
	@throw p;
	
	if (EC_KEY_check_key(self.key_curve) != 1)
	@throw p;
	
	privatKey = (BIGNUM *)EC_KEY_get0_private_key(self.key_curve);
	
	char *privat_key_char = BN_bn2hex(privatKey);
	char *public_key_char = EC_POINT_point2hex(key_group, self.PublicKeyPoint, POINT_CONVERSION_UNCOMPRESSED, bn_ctx);
	char *public_x_key_char = BN_bn2hex(publicKeyXBN);
	char *public_y_key_char = BN_bn2hex(publicKeyYBN);
	
	self.PrivatKey = [NSString stringWithCString:privat_key_char encoding:NSUTF8StringEncoding];
	self.PublicKey = [NSString stringWithCString:public_key_char encoding:NSUTF8StringEncoding];
	self.PublicKeyX = [NSString stringWithCString:public_x_key_char encoding:NSUTF8StringEncoding];
	self.PublicKeyY = [NSString stringWithCString:public_y_key_char encoding:NSUTF8StringEncoding];
	//=======================
	
	return self;
}

-(EC_POINT*)generatePublicKey:(NSString*)publicKey_x_str
				  publicKey_y:(NSString*)publicKey_y_str
{
	EC_POINT *publicKeyPoint = NULL;
	BIGNUM *publicKeyX = BN_CTX_get(bn_ctx);
	BIGNUM *publicKeyY = BN_CTX_get(bn_ctx);
	
	//=======================
	privatKey = BN_CTX_get(bn_ctx);
	BN_hex2bn(&publicKeyX, [publicKey_x_str UTF8String]);
	BN_hex2bn(&publicKeyY, [publicKey_y_str UTF8String]);
	//=======================
	
	NSException *p = [NSException exceptionWithName:@"" reason:@"" userInfo:nil];
	
	if ((publicKeyPoint = EC_POINT_new(key_group)) == NULL)
	@throw p;
	
	if (EC_POINT_set_affine_coordinates_GFp(key_group, publicKeyPoint, publicKeyX, publicKeyY, bn_ctx) != 1)
	@throw p;
	
	return publicKeyPoint;
}


-(EC_POINT*)generatePublicKey:(NSString*)publicKey_str
{
	EC_POINT *publicKeyPoint = NULL;
	
	NSException *p = [NSException exceptionWithName:@"" reason:@"" userInfo:nil];
	
	if ((self.PublicKeyPoint = EC_POINT_new(key_group)) == NULL)
	@throw p;
	
	EC_POINT_hex2point(key_group, [publicKey_str UTF8String], publicKeyPoint, bn_ctx);
	
	return publicKeyPoint;
}

-(void)calculateSymmetricKeyWithOtherECDH:(EC_POINT*)otherPublicKey
{
	unsigned char *key_agreement = NULL;
	key_agreement = (unsigned char *)OPENSSL_malloc(SHA_DIGEST_LENGTH);
	ECDH_compute_key(key_agreement, SHA_DIGEST_LENGTH, otherPublicKey, self.key_curve, NULL);
	
	symmetricKey = [NSData dataWithBytes:key_agreement length:KEY_LENGTH];
	self.SymmetricKey = [self stringWithHexBytes:symmetricKey];
	
}

-(void)calculateSymmetricKey:(NSString*)other_publicKey_x
		   other_publicKey_y:(NSString*)other_publicKey_y
{
	EC_POINT *otherPublicKey = [self generatePublicKey:other_publicKey_x
										   publicKey_y:other_publicKey_y];
	
	[self calculateSymmetricKeyWithOtherECDH:otherPublicKey];
	
}

-(void)calculateSymmetricKey:(NSString*)other_publicKey
{
	EC_POINT *otherPublicKey = [self generatePublicKey:other_publicKey];
	
	[self calculateSymmetricKeyWithOtherECDH:otherPublicKey];
	
}

- (NSString*) stringWithHexBytes:(NSData*)data
{
	NSMutableString *stringBuffer = [NSMutableString stringWithCapacity:([data length] * 2)];
	const unsigned char *dataBuffer = [data bytes];
	int i;
	for (i = 0; i < [data length]; ++i) {
		//[stringBuffer appendFormat:@"%02X", (unsigned long)dataBuffer[i]];
		[stringBuffer appendFormat:@"%02lX", (unsigned long)dataBuffer[i]];
	}
	return [stringBuffer copy] ;
}

@end
