#ifndef ENCRYPTION_H
#define ENCRYPTION_H

#include <string>
#include <cstring>
#include <vector>

using namespace std;
typedef unsigned char byte;

class Encryption 
{
   private: 
   static const string CIPHER_METHOD;
   static const int KEY_BYTE_SIZE;
   static const string HASH_FUNCTION;
   static const int MAC_BYTE_SIZE;
   static const string ENCRYPTION_INFO;
   static const string AUTHENTICATION_INFO;
   
   static vector< byte > plainEncrypt( string plain, vector< byte > key,  byte* iv );   
   static vector< byte > plainDecrypt( vector< byte > cipher, vector< byte > key, vector< byte > iv );
   
   public:
   static string hash_hmac( vector< byte > ciphertext, vector< byte > key );
   static void decode( string source, string &destination );
   static void encode( string source, string &destination ); 
   static vector< byte > HKDF( vector< byte > ikm, int length, vector< byte > info, vector< byte > salt );
   static string bytesToString(vector< byte > bytes);
   static vector< byte > stringToBytes( const string& text );
   static void concatenateArrays( vector< byte>& vector3,  vector< byte > vector1, vector< byte > vector2 );


   static string encrypt( string plainText, string keyString );
   static string decrypt( string cipherText, string keyString );
};

#endif
