#include <iostream>
#include "VideoSteganography.h"

int main() {
    VideoSteganography stego;
    std::string inputVideoPath = "input.mp4"; // 输入视频路径
    std::string outputVideoPath = "output.mp4"; // 输出视频路径
    std::string secretMessage = "Hello, World!"; // 要嵌入的消息

    try {
        // 将消息嵌入视频
        stego.embedTextInVideo(inputVideoPath, outputVideoPath, secretMessage);

        // 从视频中提取消息
        std::string extractedMessage = stego.extractTextFromVideo(outputVideoPath, secretMessage.size() + 5); // 5 是结束标志的大小
        std::cout << "提取的消息: " << extractedMessage << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "发生错误: " << e.what() << std::endl;
    }

    return 0;
}
