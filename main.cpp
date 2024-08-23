#include <iostream>
#include "text_steganography.h"

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage: " << argv[0] << " <directory_path> <action> <message|file_path>" << std::endl;
        return 1;
    }

    std::string directoryPath = argv[1];
    std::string action = argv[2];
    TextSteganography stego;

    try {
        if (action == "embed") {
            std::string message = argv[3];
            stego.embedMessageInDirectory(directoryPath, message);
            std::cout << "Message embedded successfully." << std::endl;
        } else if (action == "embedFile") {
            std::string filePath = argv[3];
            stego.embedEncryptedFileInDirectory(directoryPath, filePath);
            std::cout << "Encrypted file content embedded successfully." << std::endl;
        }

        // 提取隐藏信息
        for (const auto& entry : std::filesystem::directory_iterator(directoryPath)) {
            if (stego.isTextFile(entry.path().string())) {
                std::string extractedMessage = stego.extractMessageFromFile(entry.path().string());
                std::cout << "Extracted message from " << entry.path() << ": " << extractedMessage << std::endl;
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
