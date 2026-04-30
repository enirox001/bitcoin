// Copyright (c) 2026-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_FUZZ_IPC_FUZZ_H
#define BITCOIN_TEST_FUZZ_IPC_FUZZ_H

#include <ipc/capnp/common-types.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>
#include <streams.h>
#include <univalue.h>

#include <algorithm>
#include <ios>
#include <type_traits>
#include <vector>

class IpcFuzzImplementation
{
public:
    int add(int a, int b) { return a + b; }
    COutPoint passOutPoint(COutPoint o) { return COutPoint{o.hash, o.n ^ 0xFFFFFFFFu}; }
    std::vector<uint8_t> passVectorUint8(std::vector<uint8_t> v) { std::reverse(v.begin(), v.end()); return v; }
    CScript passScript(CScript s) { s << OP_NOP; return s; }
    UniValue passUniValue(UniValue v) { return v; }
    CTransactionRef passTransaction(CTransactionRef t) { return t; }
    bool deserializeOutPoint(const std::vector<uint8_t>& bytes) { return CanDeserialize<COutPoint>(bytes); }
    bool deserializeScript(const std::vector<uint8_t>& bytes) { return CanDeserialize<CScript>(bytes); }
    bool deserializeTransaction(const std::vector<uint8_t>& bytes) { return CanDeserialize<CMutableTransaction>(bytes); }

private:
    template <typename T>
    static bool CanDeserialize(const std::vector<uint8_t>& bytes)
    {
        try {
            SpanReader stream{bytes};
            if constexpr (std::is_same_v<T, CMutableTransaction>) {
                auto wrapper{ipc::capnp::Wrap(stream)};
                [[maybe_unused]] T value{deserialize, wrapper};
            } else if constexpr (std::is_constructible_v<T, deserialize_type, SpanReader&>) {
                [[maybe_unused]] T value{deserialize, stream};
            } else {
                T value;
                stream >> value;
            }
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
};

#endif // BITCOIN_TEST_FUZZ_IPC_FUZZ_H
