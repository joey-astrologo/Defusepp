#include "encryption.h"
#include <iostream>
//crypto++
#include "cryptopp/sha.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
#include "cryptopp/hmac.h"
#include "cryptopp/osrng.h"
#include "cryptopp/aes.h"
#include "cryptopp/modes.h"

using namespace CryptoPP;

const string Encryption::CIPHER_METHOD = "AES/CBC/PKCS5Padding";
const int Encryption::KEY_BYTE_SIZE = 16;
const string Encryption::HASH_FUNCTION = "HmacSHA256";
const int Encryption::MAC_BYTE_SIZE = 32;
const string Encryption::ENCRYPTION_INFO = "DefusePHP|KeyForEncryption";
const string Encryption::AUTHENTICATION_INFO = "DefusePHP|KeyForAuthentication";


string Encryption::encrypt(string plainText, string keyString)
{
   vector< byte >  output;
   string decoded;
   
   Encryption::decode( keyString, decoded );
   vector< byte > key = Encryption::stringToBytes( decoded );
   
   vector< byte > ekey = Encryption::HKDF( key, Encryption::KEY_BYTE_SIZE, 
                          Encryption::stringToBytes(Encryption::ENCRYPTION_INFO), vector< byte >() );

   AutoSeededRandomPool prng;

   byte iv[ Encryption::KEY_BYTE_SIZE ];
   prng.GenerateBlock( iv, sizeof(iv) );
   vector< byte > ivMat(iv, iv + sizeof iv / sizeof iv[0]);

   vector< byte > ciphertext;
   
   Encryption::concatenateArrays( ciphertext, ivMat, Encryption::plainEncrypt( plainText, ekey, iv ) );
   
   vector< byte > akey = Encryption::HKDF( key, Encryption::KEY_BYTE_SIZE, Encryption::stringToBytes(Encryption::AUTHENTICATION_INFO), vector< byte >() );
   vector< byte > auth = Encryption::stringToBytes( Encryption::hash_hmac( ciphertext, akey ) );

   Encryption::concatenateArrays( output, auth, ciphertext );
   
   string finalOut = Encryption::bytesToString( output );
   string encoded;
   encode( finalOut, encoded );
   return encoded;
}
string Encryption::decrypt( string ciphertext, string keyString )
{
   string cipherDecoded, keyDecoded;
   Encryption::decode( ciphertext, cipherDecoded );
   Encryption::decode( keyString, keyDecoded );
   vector< byte > key = Encryption::stringToBytes( keyDecoded );
   vector< byte > cipherPadded = Encryption::stringToBytes( cipherDecoded );
   vector< byte >::iterator nth = cipherPadded.begin() + Encryption::MAC_BYTE_SIZE;

   vector< byte > cipher( nth, cipherPadded.end() );
      
   vector< byte > akey = Encryption::HKDF( key, Encryption::KEY_BYTE_SIZE, Encryption::stringToBytes(Encryption::AUTHENTICATION_INFO), vector< byte >() );
   vector< byte > ekey = Encryption::HKDF( key, Encryption::KEY_BYTE_SIZE,
                          Encryption::stringToBytes(Encryption::ENCRYPTION_INFO), vector< byte >() );
   vector< byte > iv( cipher.begin(), cipher.begin() + Encryption::KEY_BYTE_SIZE );
   nth = cipher.begin() + Encryption::KEY_BYTE_SIZE;
   vector< byte > extractCipher(nth, cipher.end() );
   vector< byte > plaintext = Encryption::plainDecrypt(extractCipher, ekey, iv);
   
   return Encryption::bytesToString(plaintext);
}
string Encryption::hash_hmac( vector< byte > text, vector< byte > key ) 
{
   string mac;
   string plain = Encryption::bytesToString( text );
   
   byte* k = &key[0];
   
   HMAC< SHA256 > hmac( k, Encryption::KEY_BYTE_SIZE );
   
   StringSource ss(plain, true, 
     new HashFilter(hmac,
         new StringSink(mac)
     ) // HashFilter      
   ); // StringSource
   
   return mac;
}
vector< byte > Encryption::HKDF( vector< byte > ikm, int length, vector< byte > info, vector< byte > salt ) 
{
   int digestLength = Encryption::MAC_BYTE_SIZE;
   
   if (length < 0 || length > 255 * digestLength) {
      cout << "Length of second parameter is out of range (0 <= length > 8,160);";
      exit(20); //Length of second parameter is out of range (0 <= length > 8,160)
   }
   
   if ( salt.empty() ) {
      salt.clear();
      salt.resize(digestLength); 
      fill(salt.begin(), salt.end(), 0);
   }
     
   vector< byte > prk = Encryption::stringToBytes( Encryption::hash_hmac(ikm, salt) );
   vector< byte > t;
   vector< byte > lastblock;
   
   int blockIndex = 1;
 
   for ( blockIndex = 1; t.size() < (unsigned int)length; ++blockIndex ) {
      lastblock.insert( lastblock.end(), info.begin(), info.end() );
      lastblock.push_back( static_cast< byte >( blockIndex ) );
      lastblock = Encryption::stringToBytes( Encryption::hash_hmac( lastblock, prk ) ); 
      t.insert( t.end(), lastblock.begin(), lastblock.end() );
   }
   
   vector< byte > orm( t.begin(), t.begin() + length );
   
   return orm;
}
void Encryption::concatenateArrays( vector< byte >& vector3, vector< byte > vector1, vector< byte > vector2) 
{
   vector1.insert( vector1.end(), vector2.begin(), vector2.end() );
   vector3 = vector1;
}
vector< byte > Encryption::stringToBytes( const string& text ) 
{
   vector< byte > v(text.begin(), text.end());
   return v;
}
string Encryption::bytesToString( vector< byte > byteArray ) 
{
   string plain( byteArray.begin(), byteArray.end() );
   return plain;
}
void Encryption::decode( string source, string &destination ) 
{
   destination.clear();
   StringSource ss(source, true,
      new Base64Decoder(
        new StringSink(destination)
      ) // Base64Decoder
   ); // StringSource 
}
void Encryption::encode( string source, string &destination ) 
{
   destination.clear();
   StringSource ss(source, true,
      new Base64Encoder(
        new StringSink(destination), false
      ) // Base64Encoder
   ); // StringSource     
}
vector< byte > Encryption::plainEncrypt( string plain, vector< byte >  key, byte iv[] ) 
{
   byte* k = &key[0];
   CBC_Mode< AES >::Encryption e;
   e.SetKeyWithIV( k, key.size(), iv );
   string cipher; 
   StringSource ss( plain, true, 
        new StreamTransformationFilter( e,
            new StringSink( cipher ),
            BlockPaddingSchemeDef::PKCS_PADDING
        ) // StreamTransformationFilter      
    ); // StringSource
   return Encryption::stringToBytes( cipher );
}
vector< byte > Encryption::plainDecrypt( vector< byte > cipher, vector< byte > key, vector< byte > iv )
{
   byte* k = &key[0];
   byte* ivArray = &iv[0];
   string cipherStr = Encryption::bytesToString( cipher );
   
   CBC_Mode< AES >::Decryption d;
   d.SetKeyWithIV( k, key.size(), ivArray );
   string recovered; 
   StringSource ss( cipherStr, true,
           new StreamTransformationFilter( d,
              new StringSink( recovered ),
              BlockPaddingSchemeDef::PKCS_PADDING
           ) // StreamTransformationFilter
   ); // StringSource
   return Encryption::stringToBytes( recovered );
}

