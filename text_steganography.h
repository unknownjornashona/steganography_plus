#ifndef TEXT_STEGANOGRAPHY_H
#define TEXT_STEGANOGRAPHY_H

#include <string>
#include <fstream>
#include <stdexcept>
#include <vector>
#include <filesystem>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/evp.h>

class TextSteganography {
public:
    TextSteganography();
    ~TextSteganography();
    
    void embedMessageInDirectory(const std::string& directoryPath, const std::string& message);
    void embedEncryptedFileInDirectory(const std::string& directoryPath, const std::string& filePath);
    std::string extractMessageFromFile(const std::string& filePath);
    
private:
    void writeToFile(const std::string& filePath, const std::string& data);
    std::string encodeMessage(const std::string& message);
    std::string decodeMessage(const std::string& encodedMessage);
    std::string readFile(const std::string& filePath);
    
    std::string encryptMessage(const std::string& message);
    std::string decryptMessage(const std::string& encryptedMessage);
    bool isTextFile(const std::string& filePath);
    std::string generateSharedSecret(const EC_KEY* recipientKey);
    std::string deriveSymmetricKey(const std::string& sharedSecret);
    
    EC_KEY* keyPair; // ECC 密钥对
};

#endif // TEXT_STEGANOGRAPHY_H
