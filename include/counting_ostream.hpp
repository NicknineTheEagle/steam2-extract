#include <iostream>
#include <streambuf>
#include <cstddef>

class counting_streambuf : public std::streambuf {
public:
    counting_streambuf() : byte_count_(0) {}

    std::size_t byte_count() const { return byte_count_; }

protected:
    std::streamsize xsputn(const char* s, std::streamsize n) override {
        byte_count_ += n;
        return n;
    }

    // Count single character
    int overflow(int ch) override {
        if (ch != EOF) {
            ++byte_count_;
        }
        return ch;
    }

private:
    std::size_t byte_count_;
};

class counting_ostream : public std::ostream {
public:
    counting_ostream() : std::ostream(&buf_) {}

    std::size_t byte_count() const { return buf_.byte_count(); }

private:
    counting_streambuf buf_;
};
