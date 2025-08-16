#include <utility>
#include <cstddef>

template<typename T>
class enumerate_wrapper {
public:
    explicit enumerate_wrapper(T& iterable) : iterable_(iterable) {}

    auto begin() {
        return iterator(std::begin(iterable_), 0);
    }

    auto end() {
        return iterator(std::end(iterable_), -1); // index not used for end
    }

private:
    T& iterable_;

    struct iterator {
        typename T::iterator iter;
        std::size_t index;

        iterator(typename T::iterator it, std::size_t idx) : iter(it), index(idx) {}

        bool operator!=(const iterator& other) const { return iter != other.iter; }

        void operator++() {
            ++iter;
            ++index;
        }

        auto operator*() const {
            return std::pair<std::size_t, typename T::value_type&>{index, *iter};
        }
    };
};

template<typename T>
auto enumerate(T& iterable) {
    return enumerate_wrapper<T>(iterable);
}
