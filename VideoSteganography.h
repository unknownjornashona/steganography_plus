#ifndef VIDEOSTEGANOGRAPHY_H
#define VIDEOSTEGANOGRAPHY_H

#include <opencv2/opencv.hpp>
#include <string>

class VideoSteganography {
public:
    void embedTextInVideo(const std::string& inputVideoPath, const std::string& outputVideoPath, const std::string& secretMessage);
    std::string extractTextFromVideo(const std::string& inputVideoPath, size_t messageLength);

private:
    void embedMessageInFrame(cv::Mat& frame, const std::string& message);
    std::string extractMessageFromFrame(const cv::Mat& frame, size_t messageLength);
};

#endif // VIDEOSTEGANOGRAPHY_H
