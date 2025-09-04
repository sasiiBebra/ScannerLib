#pragma once 

#ifndef DLL_EXPORT
#  ifdef _WIN32
#    define DLL_EXPORT __declspec(dllexport)
#  else
#    define DLL_EXPORT
#  endif
#endif

template<typename T>
class BlockQueue {
private:
    std::mutex mutex_;
    std::queue<T> queue_;
    std::condition_variable cv_;
    bool open_;
    size_t waiting_count_;

public:
    BlockQueue() : open_(true), waiting_count_(0) {}
    void Lock() {
        std::lock_guard<std::mutex> lock(mutex_);
        open_ = false; 
        cv_.notify_all(); 
    }
    void Push(const T& val) {
        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!open_) return;
            queue_.push(val);
        }
        cv_.notify_one();
    }
    std::optional<T> Get() {
        std::unique_lock<std::mutex> lock(mutex_);
        ++waiting_count_;
        cv_.wait(lock, [this] { return !queue_.empty() || !open_; });
        --waiting_count_;
        if (queue_.empty())
            return std::nullopt;
        T val = std::move(queue_.front());
        queue_.pop();
        return val;
    }

    bool Empty() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.empty();
    }

    size_t Size() {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }
};
