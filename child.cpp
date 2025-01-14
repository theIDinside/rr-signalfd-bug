#include <mutex>
#include <thread>
#include <vector>
#include <iostream>

int main() {
    std::vector<std::thread> threads;

    static std::mutex stdioLock{};
    for(auto i = 0; i < 5; ++i) {
        threads.emplace_back([&lock=stdioLock, i]() {
            std::lock_guard l(lock);
            std::cout << i << " says hello\n";
        });
    }

    for(auto& t : threads) {
        t.join();
    }

    return 0;
}