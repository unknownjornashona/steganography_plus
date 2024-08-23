#include "VideoSteganography.h"

// 嵌入文本到视频
void VideoSteganography::embedTextInVideo(const std::string& inputVideoPath, const std::string& outputVideoPath, const std::string& secretMessage) {
    cv::VideoCapture inputVideo(inputVideoPath);
    if (!inputVideo.isOpened()) {
        throw std::runtime_error("无法打开输入视频: " + inputVideoPath);
    }

    cv::VideoWriter outputVideo;
    int codec = cv::VideoWriter::fourcc('M', 'J', 'P', 'G'); // 编码格式
    outputVideo.open(outputVideoPath, codec, inputVideo.get(cv::CAP_PROP_FPS),
                     cv::Size(static_cast<int>(inputVideo.get(cv::CAP_PROP_FRAME_WIDTH)),
                              static_cast<int>(inputVideo.get(cv::CAP_PROP_FRAME_HEIGHT))),
                     true);

    if (!outputVideo.isOpened()) {
        throw std::runtime_error("无法创建输出视频: " + outputVideoPath);
    }

    std::string messageWithEndFlag = secretMessage + "{END}"; // 添加结束标志
    size_t messageIndex = 0;
    cv::Mat frame;

    while (true) {
        inputVideo >> frame;
        if (frame.empty()) break;

        if (messageIndex < messageWithEndFlag.size()) {
            embedMessageInFrame(frame, messageWithEndFlag.substr(messageIndex, 1)); // 嵌入单个字符
            messageIndex++;
        }
        
        outputVideo << frame; // 写入输出视频
    }

    inputVideo.release();
    outputVideo.release();
}

// 从帧中提取文本
std::string VideoSteganography::extractMessageFromFrame(const cv::Mat& frame, size_t messageLength) {
    std::string message;
    
    for (size_t i = 0; i < messageLength; ++i) {
        char ch = 0;
        for (size_t bit = 0; bit < 8; ++bit) {
            // 读取每个像素的最低有效位
            size_t pixelIndex = (i * 8 + bit) * 3; // 假定为 RGB 格式
            if (pixelIndex / frame.cols < frame.rows) { // 确保未越界
                ch |= (frame.at<cv::Vec3b>(pixelIndex / frame.cols, pixelIndex % frame.cols)[0] & 1) << (7 - bit);
            }
        }
        message += ch;
        if (message.size() > 4 && message.substr(message.size() - 5) == "{END}") {
            break; // 检查结束标志
        }
    }
    
    return message;
}

// 从视频中提取文本
std::string VideoSteganography::extractTextFromVideo(const std::string& inputVideoPath, size_t messageLength) {
    cv::VideoCapture inputVideo(inputVideoPath);
    if (!inputVideo.isOpened()) {
        throw std::runtime_error("无法打开输入视频: " + inputVideoPath);
    }

    std::string extractedMessage;
    cv::Mat frame;

    while (true) {
        inputVideo >> frame;
        if (frame.empty()) break;

        std::string messageFromFrame = extractMessageFromFrame(frame, messageLength);
        extractedMessage += messageFromFrame;
    }

    return extractedMessage;
}

// 向帧嵌入消息
void VideoSteganography::embedMessageInFrame(cv::Mat& frame, const std::string& message) {
    for (size_t bit = 0; bit < 8; ++bit) {
        char ch = message[0];
        size_t pixelIndex = bit * 3; // 假定为 RGB 格式
        frame.at<cv::Vec3b>(0, pixelIndex / frame.cols)[0] = 
            (frame.at<cv::Vec3b>(0, pixelIndex / frame.cols)[0] & ~1) | ((ch >> (7 - bit)) & 1); 
    }
}
