#include <iostream>
using std::cout;
using std::endl;

#include "cryptopp/filters.h"
#include "cryptopp/base64.h"
using namespace CryptoPP;
#include "encryption.h"
#include <string>

int main() {
   string secretKey = "+IGfyaa3jQzXo3JOi7WXRg==";
   string decodedKey, encoded, encodedKey;
   string plainText = "Cool uncle Stu balls.";
   
   Encryption::decode(secretKey, decodedKey);
   Encryption::encode(decodedKey, encodedKey);  
  
   cout << "Decoded key: " << decodedKey << endl;
   cout << "Encoded Key: " << encodedKey << endl;
  
   //string example = "PgenoeWGzf6nMIy+PUEMPObPeeiMp0e2TxbS69ttEhtSDLo2AReSu7/VQ3hPsuqXxg2apHMXH0ggoySZHrgkXCTGKNqbed1IRcui0dNuZ/A=";
   string encrypted = Encryption::encrypt( plainText, secretKey );
   string decrypted = Encryption::decrypt( encrypted, secretKey );
   //string decrypted = Encryption::decrypt( example, secretKey );
   //cout << "Example Length: " << example.length() << endl;
   //cout << example << endl; 
   cout << "Encrypted Length: " << encrypted.length() << endl;
   cout << "Encrypted Text: " << encrypted << endl;
   cout << "Decrypted Text: " << decrypted << endl;
   
   return 0;
}
