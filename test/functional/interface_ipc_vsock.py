#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test IPC with vsock transport"""

import os
import subprocess

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import assert_equal

# CID 1 is the vsock loopback address for same-host testing
# Requires vsock_loopback kernel module to be loaded
VSOCK_LOOPBACK_CID = 1

def get_vsock_port(node_index):
    return 10000 + node_index

class TestBitcoinIpcVsock(BitcoinTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 1

    def skip_test_if_missing_module(self):
        self.skip_if_no_ipc()
        if not os.path.exists('/dev/vsock'):
            self.skip('vsock not available on this platform')

    def setup_nodes(self):
        self.extra_init = [{"ipcbind": True}]
        self.extra_args = [[f"-ipcbind=vsock:{VSOCK_LOOPBACK_CID}:{get_vsock_port(0)}"]]
        super().setup_nodes()

    def test_cli(self, args, error=None):
        # Intentionally set wrong RPC password so only IPC not HTTP
        # connections work — mirrors approach in interface_ipc_cli.py
        args = [
            self.binary_paths.bitcoincli,
            f"-datadir={self.nodes[0].datadir_path}",
            "-rpcpassword=wrong",
            f"-ipcconnect=vsock:{VSOCK_LOOPBACK_CID}:{get_vsock_port(0)}",
        ] + args + ["echo", "foo"]
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        if error is None:
            assert_equal(result.stdout, '[\n  "foo"\n]\n')
        else:
            assert_equal(result.stdout, error)
        assert_equal(result.stderr, None)
        assert_equal(result.returncode, 0 if error is None else 1)

    def run_test(self):
        self.log.info("Test bitcoin-cli connects to node via vsock")
        self.test_cli([])

        self.log.info("Test vsock connection fails gracefully when node is stopped")
        self.stop_node(0)
        ipc_error = (
            f"error: timeout on transient error: Connection reset by peer\n\n"
            f"Probably bitcoin-node is not running or not listening on a "
            f"vsock address. Can be started with:\n\n"
            f"    bitcoin-node -chain=regtest "
            f"-ipcbind=vsock:{VSOCK_LOOPBACK_CID}:{get_vsock_port(0)}\n"
        )
        self.test_cli([], error=ipc_error)

        self.log.info("Test invalid vsock address format gives clean error")
        args = [
            self.binary_paths.bitcoincli,
            f"-datadir={self.nodes[0].datadir_path}",
            "-ipcconnect=vsock:invalid",
            "-getinfo"
        ]
        result = subprocess.run(
            args,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True
        )
        assert "Invalid vsock address" in result.stdout
        assert_equal(result.returncode, 1)


if __name__ == '__main__':
    TestBitcoinIpcVsock(__file__).main()
