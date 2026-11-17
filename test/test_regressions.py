#!/usr/bin/env python3
"""Regression tests for MSVC and MinGW COFF loading behavior."""

import pathlib
import os
import struct
import sys
import unittest


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ["PATH"] = str(ROOT / "test") + os.pathsep + os.environ.get("PATH", "")

import boftest  # noqa: E402


class CoffLoaderRegressionTests(unittest.TestCase):
    def run_object(self, name, *args):
        return boftest.run_bof(
            str(ROOT / "test" / name),
            commands=[{"args": list(args)}],
        )

    def test_msvc_object(self):
        result = self.run_object("crashtest.x64.o", "i:0")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["schema"], "coffloader/v2")
        self.assertEqual(result["schema_version"], 2)
        self.assertTrue(result["summary"]["ok"])
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello, no crash", result["commands"][0]["output"])

    def test_access_violation_is_still_captured(self):
        result = self.run_object("crashtest.x64.o", "i:1")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["summary"]["ok"])
        self.assertEqual(result["summary"]["crash_count"], 1)
        self.assertEqual(result["commands"][0]["status"], "crash")
        self.assertEqual(result["commands"][0]["exception"], "0xC0000005")
        self.assertEqual(
            result["commands"][0]["exception_name"],
            "EXCEPTION_ACCESS_VIOLATION",
        )
        self.assertEqual(result["commands"][0]["access_type"], "read")
        self.assertEqual(result["commands"][0]["access_addr"], "0x0")
        self.assertGreaterEqual(
            len(result["commands"][0]["exception_parameters"]), 2
        )
        self.assertEqual(
            result["commands"][0]["error"]["code"], "BOF_EXCEPTION"
        )

    def test_software_exception_reaches_frame_handler(self):
        result = self.run_object("software_exception.x64.o")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["summary"]["ok"])
        self.assertEqual(result["summary"]["crash_count"], 0)
        self.assertEqual(result["commands"][0]["status"], "ok")
        self.assertIn("software-exception:handled:0x000006BA", result["commands"][0]["output"])

        inspection = boftest.run_bof(
            str(ROOT / "test" / "software_exception.x64.o"), inspect=True
        )["inspection"]
        self.assertGreaterEqual(inspection["unwind"]["pdata_sections"], 1)
        self.assertGreaterEqual(inspection["unwind"]["registered_tables"], 1)
        self.assertGreaterEqual(inspection["unwind"]["function_count"], 1)

    def test_mingw_bare_functions(self):
        result = self.run_object("mingw_bare_function.x64.o")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("bare-function:ok", result["commands"][0]["output"])

    def test_mingw_bare_data_is_not_a_thunk(self):
        result = self.run_object("mingw_bare_data.x64.o")
        self.assertEqual(result["status"], "completed")
        output = result["commands"][0]["output"]
        self.assertIn("bare-data __argc=", output)
        self.assertNotIn("__argc=9727", output)

    def test_beacon_key_value_remove_uses_its_own_slot(self):
        result = self.run_object("kv_store.x64.o")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["summary"]["ok"])
        self.assertIn("kv-store:ok", result["commands"][0]["output"])

    def test_callback_error_cannot_false_pass(self):
        result = self.run_object("callback_error.x64.o")
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["exit_code"], 1)
        self.assertFalse(result["summary"]["ok"])
        self.assertEqual(result["summary"]["callback_error_count"], 1)
        self.assertEqual(result["commands"][0]["status"], "error")
        self.assertEqual(
            result["commands"][0]["error"]["code"], "BOF_CALLBACK_ERROR"
        )

    def test_inspect_reports_import_dispatch_without_execution(self):
        result = boftest.run_bof(
            str(ROOT / "test" / "mingw_bare_function.x64.o"),
            inspect=True,
        )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["schema"], "coffloader/v2")
        self.assertEqual(result["phase"], "inspect")
        inspection = result["inspection"]
        self.assertEqual(inspection["compiler_profile"], "mingw-compatible")
        self.assertGreaterEqual(inspection["dispatch"]["trampolines"], 3)
        self.assertTrue(all(item["resolved"] for item in inspection["imports"]))

    def test_unresolved_import_cannot_false_pass(self):
        results = boftest.run_test_spec({
            "bof": str(ROOT / "test" / "badimport.x64.o"),
            "tests": [{"name": "unresolved", "args": []}],
        })
        self.assertFalse(results[0]["passed"])
        self.assertIn("unresolved_imports", results[0]["reason"])

    def test_mixed_packed_multi_command(self):
        result = boftest.run_bof(
            str(ROOT / "test" / "crashtest.x64.o"),
            commands=[
                {"packed": struct.pack("<I", 0)},
                {"args": ["i:0"]},
            ],
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["commands"]), 2)
        self.assertTrue(all(c["status"] == "ok" for c in result["commands"]))

    def test_truncated_object_is_rejected_cleanly(self):
        source = (ROOT / "test" / "crashtest.x64.o").read_bytes()
        malformed = ROOT / "test" / ".tmp_truncated.o"
        try:
            malformed.write_bytes(source[:32])
            result = boftest.run_bof(str(malformed))
        finally:
            malformed.unlink(missing_ok=True)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["legacy_status"], "load_error")
        self.assertEqual(result["phase"], "parse")
        self.assertEqual(result["error"]["code"], "COFF_SECTION_TABLE_OUT_OF_BOUNDS")
        self.assertEqual(result["exit_code"], 1)

    def test_oversized_symbol_count_is_rejected_cleanly(self):
        data = bytearray((ROOT / "test" / "crashtest.x64.o").read_bytes())
        struct.pack_into("<L", data, 12, 0x80000000)
        malformed = ROOT / "test" / ".tmp_symbol_count.o"
        try:
            malformed.write_bytes(data)
            result = boftest.run_bof(str(malformed))
        finally:
            malformed.unlink(missing_ok=True)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["phase"], "parse")
        self.assertEqual(
            result["error"]["code"], "COFF_SYMBOL_COUNT_UNSUPPORTED"
        )
        self.assertEqual(result["exit_code"], 1)

    def test_invalid_relocation_symbol_is_rejected_cleanly(self):
        data = bytearray((ROOT / "test" / "crashtest.x64.o").read_bytes())
        _, section_count, _, _, symbol_count, _, _ = struct.unpack_from(
            "<HHLLLHH", data, 0
        )
        relocation_offset = None
        for index in range(section_count):
            section_offset = 20 + index * 40
            pointer = struct.unpack_from("<L", data, section_offset + 24)[0]
            count = struct.unpack_from("<H", data, section_offset + 32)[0]
            if count:
                relocation_offset = pointer
                break
        self.assertIsNotNone(relocation_offset)
        struct.pack_into("<L", data, relocation_offset + 4, symbol_count + 1)

        malformed = ROOT / "test" / ".tmp_bad_relocation.o"
        try:
            malformed.write_bytes(data)
            result = boftest.run_bof(str(malformed))
        finally:
            malformed.unlink(missing_ok=True)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["legacy_status"], "load_error")
        self.assertEqual(result["phase"], "relocate")
        self.assertEqual(result["error"]["code"], "COFF_BAD_SYMBOL_INDEX")
        self.assertEqual(result["exit_code"], 1)

    def test_malformed_pdata_is_rejected_cleanly(self):
        data = bytearray((ROOT / "test" / "crashtest.x64.o").read_bytes())
        _, section_count, _, _, _, _, _ = struct.unpack_from(
            "<HHLLLHH", data, 0
        )
        found = False
        for index in range(section_count):
            section_offset = 20 + index * 40
            name = bytes(data[section_offset : section_offset + 8]).rstrip(b"\0")
            if name == b".pdata":
                size = struct.unpack_from("<L", data, section_offset + 16)[0]
                struct.pack_into("<L", data, section_offset + 16, size + 1)
                found = True
                break
        self.assertTrue(found)

        malformed = ROOT / "test" / ".tmp_bad_pdata.o"
        try:
            malformed.write_bytes(data)
            result = boftest.run_bof(str(malformed))
        finally:
            malformed.unlink(missing_ok=True)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["phase"], "unwind")
        self.assertEqual(result["error"]["code"], "COFF_PDATA_SIZE_INVALID")
        self.assertEqual(result["exit_code"], 1)


if __name__ == "__main__":
    unittest.main()
