#include <fstream>
#include <string>
#include <type_traits>
#include <cstdint>
#include <stdexcept>
#include <bit>

enum class endian_type {
    little,
    big
};

class file_writer {
public:
    file_writer(const std::string& filename, std::ios::openmode mode = std::ios::binary)
        : output_stream(filename, mode) {
        if (!output_stream.is_open()) {
            throw std::runtime_error("failed to open file: " + filename);
        }
        target_endian = std::endian::native == std::endian::little
                        ? endian_type::little
                        : endian_type::big;
    }

    void set_endian(endian_type endian) {
        target_endian = endian;
    }


    template <typename T>
    void write_int(T value) {

        if ((std::endian::native == std::endian::little && target_endian == endian_type::big) ||
            (std::endian::native == std::endian::big && target_endian == endian_type::little)) {
            value = std::byteswap(value);
        }

        output_stream.write(reinterpret_cast<const char*>(&value), sizeof(T));
    }

    void write_string(const std::string& str) {
        output_stream.write(str.data(), str.size());
    }

    template <typename T>
    void write_struct(const T* struct_ptr) {
        static_assert(std::is_trivially_copyable_v<T>, "write_struct requires trivially copyable type");

        output_stream.write(reinterpret_cast<const char*>(struct_ptr), sizeof(T));
    }
    template<typename T>
    inline void write_data(const T* Ts, std::size_t num_ts){
        output_stream.write(reinterpret_cast<const char*>(Ts), sizeof(T) * num_ts);
    }

    inline std::streamsize tell(){
        return output_stream.tellp();
    }
    inline void seek(std::streamsize pos){
        output_stream.seekp(pos);
    }
private:
    std::ofstream output_stream;
    endian_type target_endian;
};
