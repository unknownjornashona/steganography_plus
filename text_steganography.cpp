#include "text_steganography.h"

// 构造函数，生成 ECC 密钥对
TextSteganography::TextSteganography() {
    keyPair = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(keyPair);
}

// 析构函数，释放ECC密钥
TextSteganography::~TextSteganography() {
    EC_KEY_free(keyPair);
}

// 生成共享密钥
std::string TextSteganography::generateSharedSecret(const EC_KEY* recipientKey) {
    int keySize = EC_GROUP_get_degree(EC_KEY_get0_group(keyPair));
    unsigned char* sharedSecret = new unsigned char[keySize / 8];

    // 生成共享密钥
    ECDH_compute_key(sharedSecret, keySize / 8, EC_KEY_get0_public_key(recipientKey), keyPair, nullptr);
    
    std::string secret(sharedSecret, sharedSecret + (keySize / 8));
    delete[] sharedSecret;

    return secret;
}

// 导出对称密钥
std::string TextSteganography::deriveSymmetricKey(const std::string& sharedSecret) {
    unsigned char symKey[16]; // 128 位对称密钥
    if (1 != PKCS5_PBKDF2_HMAC(sharedSecret.c_str(), sharedSecret.length(), nullptr, 0, 1000, EVP_sha256(), sizeof(symKey), symKey)) {
        throw std::runtime_error("Key Derivation Failed");
    }
    return std::string(reinterpret_cast<char*>(symKey), sizeof(symKey));
}

// ECC 加密
std::string TextSteganography::encryptMessage(const std::string& message) {
    // 此处创建接收者的密钥对（例如，模拟接收者）
    EC_KEY* recipientKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(recipientKey);

    // 生成共享密钥
    std::string sharedSecret = generateSharedSecret(recipientKey);
    std::string symKey = deriveSymmetricKey(sharedSecret);

    // 使用对称密钥加密消息
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    std::string ciphertext(message.size() + EVP_CIPHER_block_size(EVP_aes_128_cbc()), '\0');

    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)symKey.data(), NULL);
    EVP_EncryptUpdate(ctx, (unsigned char*)ciphertext.data(), &len, (unsigned char*)message.data(), message.size());
    ciphertext.resize(len);
    EVP_EncryptFinal_ex(ctx, (unsigned char*)ciphertext.data() + len, &len);
    ciphertext.resize(ciphertext.size() + len);
    EVP_CIPHER_CTX_free(ctx);

    // 清理
    EC_KEY_free(recipientKey);

    return ciphertext;
}

// ECC 解密
std::string TextSteganography::decryptMessage(const std::string& encryptedMessage) {
    // 此处应提供接收者的密钥对
    EC_KEY* recipientKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    EC_KEY_generate_key(recipientKey);

    // 假设我们已经获得了共享密钥
    std::string sharedSecret = generateSharedSecret(keyPair); // 假设我们有发送方的公钥
    std::string symKey = deriveSymmetricKey(sharedSecret);

    // 使用对称密钥解密消息
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    std::string decryptedMessage(encryptedMessage.size(), '\0');

    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, (unsigned char*)symKey.data(), NULL);
    EVP_DecryptUpdate(ctx, (unsigned char*)decryptedMessage.data(), &len, (unsigned char*)encryptedMessage.data(), encryptedMessage.size());
    decryptedMessage.resize(len);
    EVP_DecryptFinal_ex(ctx, (unsigned char*)decryptedMessage.data() + len, &len);
    decryptedMessage.resize(decryptedMessage.size() + len);
    EVP_CIPHER_CTX_free(ctx);

    // 清理
    EC_KEY_free(recipientKey);

    return decryptedMessage;
}

std::string TextSteganography::readFile(const std::string& filePath) {
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Could not open file for reading: " + filePath);
    }
    return std::string((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
}

void TextSteganography::embedMessageInDirectory(const std::string& directoryPath, const std::string& message) {
    std::string encryptedMessage = encryptMessage(message);

    for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
        if (isTextFile(entry.path().string())) {
            std::ifstream inputFile(entry.path());
            if (!inputFile.is_open()) {
                throw std::runtime_error("Could not open text file for reading: " + entry.path().string());
            }

            std::string textContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
            inputFile.close();

            std::string encodedMessage = encodeMessage(encryptedMessage);
            size_t messageIndex = 0;

            for (size_t i = 0; i < textContent.size() && messageIndex < encodedMessage.size(); ++i) {
                if (textContent[i] == ' ') {
                    textContent[i] = (encodedMessage[messageIndex] == '1') ? '\t' : ' ';
                    messageIndex++;
                }
            }

            writeToFile(entry.path().string(), textContent);
        }
    }
}

void TextSteganography::embedEncryptedFileInDirectory(const std::string& directoryPath, const std::string& filePath) {
    std::string encryptedContent = readFile(filePath);

    for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
        if (isTextFile(entry.path().string())) {
            std::ifstream inputFile(entry.path());
            if (!inputFile.is_open()) {
                throw std::runtime_error("Could not open text file for reading: " + entry.path().string());
            }

            std::string textContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
            inputFile.close();

            std::string encodedMessage = encodeMessage(encryptedContent);
            size_t messageIndex = 0;

            for (size_t i = 0; i < textContent.size() && messageIndex < encodedMessage.size(); ++i) {
                if (textContent[i] == ' ') {
                    textContent[i] = (encodedMessage[messageIndex] == '1') ? '\t' : ' ';
                    messageIndex++;
                }
            }

            writeToFile(entry.path().string(), textContent);
        }
    }
}

bool TextSteganography::isTextFile(const std::string& filePath) {
    return filePath.ends_with(".txt");
}

void TextSteganography::writeToFile(const std::string& filePath, const std::string& data) {
    std::ofstream outputFile(filePath);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Could not write to text file: " + filePath);
    }
    outputFile << data;
    outputFile.close();
}

std::string TextSteganography::encodeMessage(const std::string& message) {
    std::string encoded;
    for (char ch : message) {
        for (int i = 7; i >= 0; --i) {
            encoded += (ch & (1 << i)) ? '1' : '0';
        }
    }
    return encoded;
}

std::string TextSteganography::decodeMessage(const std::string& encodedMessage) {
    std::string decoded;
    for (size_t i = 0; i < encodedMessage.size(); i += 8) {
        char byte = 0;
        for (size_t j = 0; j < 8; ++j) {
            byte = (byte << 1) | (encodedMessage[i + j] - '0');
        }
        decoded += byte;
    }
    return decoded;
}

std::string TextSteganography::extractMessageFromFile(const std::string& filePath) {
    std::ifstream inputFile(filePath);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Could not open text file for reading: " + filePath);
    }

    std::string textContent((std::istreambuf_iterator<char>(inputFile)), std::istreambuf_iterator<char>());
    inputFile.close();

    std::string encodedMessage;
    for (char ch : textContent) {
        if (ch == '\t') {
            encodedMessage += '1';
        } else if (ch == ' ') {
            encodedMessage += '0';
        }
    }

    std::string encryptedMessage = decodeMessage(encodedMessage);
    return decryptMessage(encryptedMessage);
}
