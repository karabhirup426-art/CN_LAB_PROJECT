"""
test_ftp.py
Unit tests for FTP server and client (RFC 959).
Tests run against a temporary server instance on an ephemeral port.

Run with:
    python -m unittest test_ftp -v
"""

import os
import sys
import time
import hashlib
import unittest
import threading

from ftp_server import FTPServer
from ftp_client import FTPClient


class TestFTP(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.test_host = "127.0.0.1"
        cls.test_port = 2126
        cls.test_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "test_tmp"))
        cls.storage_dir = os.path.join(cls.test_dir, "storage")
        cls.client_dir = os.path.join(cls.test_dir, "client")

        os.makedirs(cls.storage_dir, exist_ok=True)
        os.makedirs(cls.client_dir, exist_ok=True)

        with open(os.path.join(cls.storage_dir, "hello.txt"), "w") as f:
            f.write("Hello CN Lab!")

        cls.server = FTPServer(host=cls.test_host, port=cls.test_port, root_dir=cls.storage_dir)
        cls.server_thread = threading.Thread(target=cls.server.start, daemon=True)
        cls.server_thread.start()
        time.sleep(0.5)

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        import shutil
        if os.path.exists(cls.test_dir):
            shutil.rmtree(cls.test_dir, ignore_errors=True)

    def setUp(self):
        self.client = FTPClient(host=self.test_host, port=self.test_port, debug=False)
        self.assertTrue(self.client.connect())

    def tearDown(self):
        if self.client.is_connected:
            self.client.disconnect()

    def test_01_auth_failure(self):
        self.client.send_cmd("USER student")
        resp = self.client.send_cmd("PASS wrongpass")
        self.assertEqual(self.client.get_code(resp), 530)

    def test_02_auth_success(self):
        self.assertTrue(self.client.login("student", "cnlab2026"))

    def test_03_pwd_and_cwd(self):
        self.client.login("admin", "admin123")
        resp = self.client.send_cmd("PWD")
        self.assertEqual(self.client.get_code(resp), 257)

    def test_04_directory_traversal_jail(self):
        self.client.login("admin", "admin123")
        resp = self.client.send_cmd("CWD ../../")
        pwd = self.client.send_cmd("PWD")
        self.assertIn('"/"', pwd)

    def test_05_upload_download_binary_md5(self):
        self.client.login("user", "password")
        data = b"FTP_SOCKET_BINARY_TEST_DATA_" + os.urandom(32768)
        upload_path = os.path.join(self.client_dir, "to_upload.bin")
        with open(upload_path, "wb") as f:
            f.write(data)
        src_md5 = hashlib.md5(data).hexdigest()

        # Upload
        self.client.upload_file(upload_path, "uploaded.bin")

        # Check server storage
        self.assertTrue(os.path.exists(os.path.join(self.storage_dir, "uploaded.bin")))

        # Download back
        down_path = os.path.join(self.client_dir, "from_server.bin")
        self.client.download_file("uploaded.bin", down_path)

        with open(down_path, "rb") as f:
            down_md5 = hashlib.md5(f.read()).hexdigest()

        self.assertEqual(src_md5, down_md5)

    def test_06_size_and_delete(self):
        self.client.login("admin", "admin123")
        size_resp = self.client.send_cmd("SIZE hello.txt")
        self.assertEqual(self.client.get_code(size_resp), 213)
        self.assertEqual(size_resp.split()[1], "13")

        del_resp = self.client.send_cmd("DELE hello.txt")
        self.assertEqual(self.client.get_code(del_resp), 250)


if __name__ == "__main__":
    unittest.main()
