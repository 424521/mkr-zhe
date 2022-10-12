

#ifndef THREADPOOL_H
#define THREADPOOL_H

#include <mutex>
#include <condition_variable>
#include <queue>
#include <thread>
#include <functional>
class ThreadPool {
public:
    //构造函数创建线程池
    explicit ThreadPool(size_t threadCount = 8): pool_(std::make_shared<Pool>()) {
            assert(threadCount > 0);
            for(size_t i = 0; i < threadCount; i++) {
                std::thread([pool = pool_] {
                    std::unique_lock<std::mutex> locker(pool->mtx);
                    while(true) {
                        if(!pool->tasks.empty()) {
                            //从工作队列中取出第一个任务
                            auto task = std::move(pool->tasks.front());
                            pool->tasks.pop();
                            locker.unlock();
                            task();
                            locker.lock();
                        } 
                        else if(pool->isClosed) break;
                        else pool->cond.wait(locker);
                    }
                }).detach();
            }
    }

    ThreadPool() = default;

    ThreadPool(ThreadPool&&) = default;
    
    ~ThreadPool() {
        if(static_cast<bool>(pool_)) {
            {
                std::lock_guard<std::mutex> locker(pool_->mtx);
                pool_->isClosed = true;
            }
            pool_->cond.notify_all(); //通知连接池里面所有的连接对象，线程池释放了
        }
    }

    template<class F>
    void AddTask(F&& task) {
        {
            std::lock_guard<std::mutex> locker(pool_->mtx);
            pool_->tasks.emplace(std::forward<F>(task));
        }
        pool_->cond.notify_one(); //如果一个任务来了后，就通知线程池里面的一个等待线程，可以取任务了
    }

private:
    struct Pool {
        std::mutex mtx;    //互斥锁
        std::condition_variable cond; //条件变量
        bool isClosed;          //是否关闭线程池
        std::queue<std::function<void()>> tasks; //工作队列，主线程把任务往里面放，然后线程池里面激活一个线程去取工作队列里面的数据，进行处理
    };
    std::shared_ptr<Pool> pool_;
};


#endif //THREADPOOL_H