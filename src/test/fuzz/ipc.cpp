// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/ipc_fuzz.capnp.h>
#include <test/fuzz/ipc_fuzz.capnp.proxy.h>
#include <test/fuzz/ipc_fuzz.h>
#include <test/fuzz/util.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/check.h>
#include <util/strencodings.h>

#include <capnp/rpc.h>
#include <capnp/capability.h>
#include <kj/memory.h>
#include <mp/proxy.h>
#include <mp/proxy-io.h>
#include <mp/util.h>
#include <condition_variable>
#include <deque>
#include <future>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace {
class IpcFuzzSetup
{
public:
    IpcFuzzSetup()
        : m_loop_thread([&] {
              mp::EventLoop loop("ipc-fuzz", [](mp::LogMessage message) {
                  if (message.level == mp::Log::Raise) throw std::runtime_error(message.message);
              });
              auto pipe = loop.m_io_context.provider->newTwoWayPipe();

              auto server_connection = std::make_unique<mp::Connection>(
                  loop,
                  kj::mv(pipe.ends[0]),
                  [&](mp::Connection& connection) {
                      auto server_proxy = kj::heap<mp::ProxyServer<test::fuzz::messages::IpcFuzzInterface>>(
                          std::make_shared<IpcFuzzImplementation>(), connection);
                      return capnp::Capability::Client(kj::mv(server_proxy));
                  });
              server_connection->onDisconnect([&] { server_connection.reset(); });

              auto client_connection = std::make_unique<mp::Connection>(loop, kj::mv(pipe.ends[1]));
              auto client_proxy = std::make_unique<mp::ProxyClient<test::fuzz::messages::IpcFuzzInterface>>(
                  client_connection->m_rpc_system->bootstrap(mp::ServerVatId().vat_id)
                      .castAs<test::fuzz::messages::IpcFuzzInterface>(),
                  client_connection.get(),
                  /* destroy_connection= */ true);
              (void)client_connection.release();

              m_client_promise.set_value(std::move(client_proxy));
              loop.loop();
          }),
          m_client_thread([this] { ClientLoop(); })
    {
        m_client = m_client_promise.get_future().get();
    }

    ~IpcFuzzSetup() = delete;

    int Add(int a, int b)
    {
        return CallOnClientThreadAndWait([&](auto& client) { return client.add(a, b); });
    }

    COutPoint PassOutPoint(const COutPoint& outpoint)
    {
        return CallOnClientThreadAndWait([&](auto& client) { return client.passOutPoint(outpoint); });
    }

    std::vector<uint8_t> PassVectorUint8(const std::vector<uint8_t>& value)
    {
        return CallOnClientThreadAndWait([&](auto& client) { return client.passVectorUint8(value); });
    }

    CScript PassScript(const CScript& script)
    {
        return CallOnClientThreadAndWait([&](auto& client) { return client.passScript(script); });
    }

private:
    // Route all ProxyClient calls through a dedicated worker thread so libmultiprocess thread-local client state
    // is never initialized on the main fuzzing thread, which avoids shutdown-order failures.
    template <typename Fn>
    auto CallOnClientThreadAndWait(Fn&& fn) -> std::invoke_result_t<Fn, mp::ProxyClient<test::fuzz::messages::IpcFuzzInterface>&>
    {
        using Result = std::invoke_result_t<Fn, mp::ProxyClient<test::fuzz::messages::IpcFuzzInterface>&>;
        auto promise = std::make_shared<std::promise<Result>>();
        auto future = promise->get_future();
        CallOnClientThread([this, fn = std::forward<Fn>(fn), promise]() mutable {
            try {
                promise->set_value(fn(*m_client));
            } catch (...) {
                promise->set_exception(std::current_exception());
            }
        });
        return future.get();
    }

    template <typename Fn>
    void CallOnClientThread(Fn&& fn)
    {
        {
            std::lock_guard<std::mutex> lock{m_client_mutex};
            m_client_queue.emplace_back(std::forward<Fn>(fn));
        }
        m_client_cv.notify_one();
    }

    void ClientLoop()
    {
        while (true) {
            std::function<void()> fn;
            {
                std::unique_lock<std::mutex> lock{m_client_mutex};
                m_client_cv.wait(lock, [this] { return m_stop || !m_client_queue.empty(); });
                if (m_stop && m_client_queue.empty()) return;
                fn = std::move(m_client_queue.front());
                m_client_queue.pop_front();
            }
            fn();
        }
    }

    std::unique_ptr<mp::ProxyClient<test::fuzz::messages::IpcFuzzInterface>> m_client;
    std::promise<std::unique_ptr<mp::ProxyClient<test::fuzz::messages::IpcFuzzInterface>>> m_client_promise;
    std::thread m_loop_thread;
    std::thread m_client_thread;
    std::mutex m_client_mutex;
    std::condition_variable m_client_cv;
    std::deque<std::function<void()>> m_client_queue;
    bool m_stop{false};
};

IpcFuzzSetup* g_setup{nullptr};

void initialize_ipc()
{
    static const auto testing_setup = MakeNoLogFileContext<>();
    (void)testing_setup;
    if (!g_setup) g_setup = new IpcFuzzSetup();
}

FUZZ_TARGET(ipc, .init = initialize_ipc)
{
    FuzzedDataProvider fuzzed_data_provider(buffer.data(), buffer.size());
    auto& ipc = *g_setup;

    LIMITED_WHILE(fuzzed_data_provider.ConsumeBool(), 64) {
        CallOneOf(
            fuzzed_data_provider,
            [&] {
                static constexpr int MIN_ADD{-1'000'000};
                static constexpr int MAX_ADD{1'000'000};
                const int a = fuzzed_data_provider.ConsumeIntegralInRange<int>(MIN_ADD, MAX_ADD);
                const int b = fuzzed_data_provider.ConsumeIntegralInRange<int>(MIN_ADD, MAX_ADD);
                assert(ipc.Add(a, b) == a + b);
            },
            [&] {
                COutPoint outpoint{Txid::FromUint256(ConsumeUInt256(fuzzed_data_provider)),
                                   fuzzed_data_provider.ConsumeIntegral<uint32_t>()};
                COutPoint expected{outpoint.hash, outpoint.n ^ 0xFFFFFFFFu};
                assert(ipc.PassOutPoint(outpoint) == expected);
            },
            [&] {
                std::vector<uint8_t> value = ConsumeRandomLengthByteVector<uint8_t>(fuzzed_data_provider, 512);
                if (value.empty()) value.push_back(0);
                std::vector<uint8_t> expected{value.rbegin(), value.rend()};
                assert(ipc.PassVectorUint8(value) == expected);
            },
            [&] {
                CScript script{ConsumeScript(fuzzed_data_provider)};
                CScript expected{script};
                expected << OP_NOP;
                assert(ipc.PassScript(script) == expected);
            });
    }
}
} // namespace
