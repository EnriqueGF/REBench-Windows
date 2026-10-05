import json
import copy
import random
import struct
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "private"))
import benchmark
from hard.build_tls import KEYS as TLS_KEYS, pe_tls_callbacks, reference as tls_reference
from hard.build_stream import KEYS as STREAM_KEYS, reference as stream_reference
from hard.build_stream2 import KEYS as STREAM2_KEYS, reference as stream2_reference
from hard.build_dump import COOKIE as DUMP_COOKIE, parse_dump


class BenchmarkTests(unittest.TestCase):
    @staticmethod
    def pe_reader(path):
        raw = path.read_bytes()
        pe = struct.unpack_from("<I", raw, 0x3C)[0]
        assert raw[:2] == b"MZ" and raw[pe:pe + 4] == b"PE\0\0"
        optional = pe + 24
        sections = optional + struct.unpack_from("<H", raw, pe + 20)[0]
        count = struct.unpack_from("<H", raw, pe + 6)[0]

        def offset(rva):
            for i in range(count):
                section = sections + 40 * i
                _, va, raw_size, pointer = struct.unpack_from("<IIII", raw, section + 8)
                if va <= rva < va + raw_size:
                    return pointer + rva - va
            raise AssertionError(f"Unmapped RVA: {rva:#x}")

        return raw, optional, offset

    def test_pe_fixture_has_valid_mapping_and_relocation(self):
        binary = (ROOT / "public/artifacts/pe64/sample_pe.bin").read_bytes()
        pe_offset = struct.unpack_from("<I", binary, 0x3C)[0]
        self.assertEqual(binary[pe_offset:pe_offset + 4], b"PE\0\0")
        optional = pe_offset + 24
        self.assertEqual(struct.unpack_from("<H", binary, optional)[0], 0x20B)
        self.assertEqual(struct.unpack_from("<Q", binary, optional + 24)[0], 0x140000000)
        self.assertEqual(struct.unpack_from("<H", binary, optional + 70)[0] & 0x40, 0x40)
        sections = optional + 0xF0
        rdata = sections + 40
        self.assertEqual(struct.unpack_from("<I", binary, rdata + 12)[0], 0x2000)
        self.assertEqual(struct.unpack_from("<I", binary, rdata + 20)[0], 0x600)
        self.assertEqual(binary[0x680:0x689], b"CASE-PE64")
        self.assertEqual(struct.unpack_from("<Q", binary, 0x628)[0], 0x140001234)
        self.assertEqual(struct.unpack_from("<IIHH", binary, 0x800), (0x2000, 12, 0xA028, 0))

    def test_all_key_answers_score_full_and_missing_scores_zero(self):
        data = benchmark.cases()["cases"]
        key = benchmark.read_json(benchmark.KEY)
        submissions = [dict(case_id=c["id"], answers={q["id"]: key[c["id"]][q["id"]]["answer"] for q in c["questions"]}) for c in data]
        report = benchmark.grade(data, submissions, key)
        self.assertEqual(report["earned"], report["total"])
        self.assertEqual(report["percent"], 100)
        self.assertEqual(benchmark.grade(data, [], key)["earned"], 0)

    def test_prompt_and_json_extraction(self):
        case = next(c for c in benchmark.cases()["cases"] if c["id"] == "pe_reloc")
        prompt = benchmark.prompt_for(case)
        self.assertIn("sample_pe.bin", prompt)
        self.assertNotIn("0x180001234", prompt)
        raw = 'Final answer:\n```json\n{"case_id":"pe_reloc","answers":{"q1":"0x180001234","q2":"B","q3":"0x40000000"}}\n```'
        parsed = benchmark.extract_answer(raw, "pe_reloc")
        self.assertEqual(parsed["answers"]["q2"], "B")

    def test_agent_runner_with_configured_executable(self):
        case = next(c for c in benchmark.cases()["cases"] if c["id"] == "pe_reloc")
        fake = ROOT / "tests/fake_agent.py"
        result = benchmark.run_case(case, "agy", {"profiles": {"agy": [sys.executable, str(fake), "{prompt}"]}}, 10)
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(result["submission"]["answers"]["q2"], "B")

    def test_expert_pe_fixtures_are_live_and_secrets_are_encoded(self):
        key = benchmark.read_json(benchmark.KEY)
        license_exe = ROOT / "public/artifacts/hard_license/license_probe.exe"
        vm_exe = ROOT / "public/artifacts/hard_vm/vm_guard.exe"
        current = key["hard_license"]["q1"]["answer"]
        retired = key["hard_license"]["q2"]["answer"]
        vm_secret = key["hard_vm"]["q1"]["answer"]
        self.assertNotIn(current.encode(), license_exe.read_bytes())
        self.assertNotIn(vm_secret.encode(), vm_exe.read_bytes())
        self.assertEqual(subprocess.run([str(license_exe), current], capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run([str(license_exe), retired], capture_output=True).returncode, 0)
        self.assertEqual(subprocess.run([str(vm_exe), vm_secret], capture_output=True).returncode, 0)
        self.assertNotEqual(subprocess.run([str(vm_exe), "A" * 16], capture_output=True).returncode, 0)

    def test_pipeline_dsl_matches_pe_on_both_branches_and_hidden_values(self):
        program = benchmark.read_json(benchmark.KEY)["hard_pipeline"]["q1"]["answer"]
        executable = ROOT / "public/artifacts/hard_pipeline/mix_oracle.exe"
        rng = random.Random(20261004)
        pairs = [(0, 0), (0x20, 0), (0xFFFFFFFFFFFFFFFF, 0x20)]
        pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(12)]
        for x, y in pairs:
            process = subprocess.run([str(executable), hex(x), hex(y)], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(benchmark.eval_pipeline64(program, x, y), int(process.stdout.strip(), 16))
        self.assertEqual(benchmark.pipeline64_points(program, program, 50), 50)
        wrong_branch = copy.deepcopy(program)
        wrong_branch["steps"][6]["b"] = "0x0"
        earned = benchmark.pipeline64_points(wrong_branch, program, 50)
        self.assertGreater(earned, 0)
        self.assertLess(earned, 50)

    def test_aob_signature_generalizes_to_hidden_build(self):
        expected = benchmark.read_json(benchmark.KEY)["hard_pattern_open"]["q1"]["answer"]
        self.assertEqual(benchmark.aob_points(expected["pattern"], expected, 40), 40)
        exact_v1 = "8B 81 A8 02 00 00 35 19 7E 5C A3 05 03 2A 4F 17 C1 C8 1D C3"
        self.assertEqual(benchmark.aob_points(exact_v1, expected, 40), 10)
        self.assertEqual(benchmark.aob_points("?? " * 20, expected, 40), 0)

    def test_tls_callback_rewrites_decoys_and_dsl_generalizes(self):
        key = benchmark.read_json(benchmark.KEY)["hard_tls_state"]
        exe = ROOT / "public/artifacts/hard_tls/tls_oracle.exe"
        callback_rva = int(key["q2"]["answer"], 0)
        self.assertIn(callback_rva, pe_tls_callbacks(exe))
        self.assertNotIn(struct.pack("<Q", TLS_KEYS[0]), exe.read_bytes())
        program = key["q1"]["answer"]
        rng = random.Random(0xC0DE2026)
        pairs = [(0, 0), (0x200, 0), (0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF)]
        pairs += [(rng.getrandbits(64), rng.getrandbits(64)) for _ in range(20)]
        for x, y in pairs:
            process = subprocess.run([str(exe), hex(x), hex(y)], capture_output=True, text=True)
            self.assertEqual(process.returncode, 0)
            expected = tls_reference(x, y)
            self.assertEqual(int(process.stdout.strip(), 16), expected)
            self.assertEqual(benchmark.eval_pipeline64(program, x, y), expected)
        self.assertEqual(benchmark.pipeline64_points(program, program, 100), 100)
        corrupted = copy.deepcopy(program)
        corrupted["tables"]["keys"][0] = "0x0"
        self.assertLess(benchmark.pipeline64_points(corrupted, program, 100), 100)
        nested = copy.deepcopy(program)
        nested["steps"][4]["body"].append({"op": "loop", "count": 1, "body": [{"dst": "r0", "op": "not", "a": "r0"}]})
        with self.assertRaises(ValueError):
            benchmark.eval_pipeline64(nested, 0, 0)

    def test_delay_import_descriptor_and_unload_copy(self):
        exe = ROOT / "public/artifacts/hard_delay/delay_probe.exe"
        raw, optional, at = self.pe_reader(exe)
        key = benchmark.read_json(benchmark.KEY)["hard_delay_import"]
        directory, size = struct.unpack_from("<II", raw, optional + 112 + 13 * 8)
        descriptor_rva = int(key["q1"]["answer"], 0)
        self.assertGreaterEqual(size, 32)
        self.assertEqual(directory, descriptor_rva)
        attrs, name, phmod, iat, names, bound, unload, _ = struct.unpack_from("<8I", raw, at(directory))
        self.assertEqual(attrs, 1)
        self.assertEqual(raw[at(name):at(name) + 11], b"USER32.dll\0")
        self.assertEqual(phmod, int(key["q5"]["answer"], 0))
        self.assertEqual(unload, int(key["q2"]["answer"], 0))
        self.assertEqual(at(unload), int(key["q3"]["answer"], 0))
        self.assertNotEqual(bound, unload)
        self.assertEqual(struct.unpack_from("<Q", raw, at(iat))[0],
                         struct.unpack_from("<Q", raw, at(unload))[0])
        self.assertEqual(struct.unpack_from("<Q", raw, at(iat))[0],
                         int(key["q4"]["answer"], 0))
        name_rva = struct.unpack_from("<Q", raw, at(names))[0]
        self.assertEqual(raw[at(name_rva) + 2:at(name_rva) + 21], b"GetForegroundWindow")
        run = subprocess.run([str(exe)], capture_output=True, text=True)
        self.assertEqual(run.returncode, 0)
        self.assertIn("unloaded=1", run.stdout)

    def test_unwind_metadata_and_stack_context(self):
        exe = ROOT / "public/artifacts/hard_unwind/unwind_probe.exe"
        raw, optional, at = self.pe_reader(exe)
        key = benchmark.read_json(benchmark.KEY)["hard_unwind_frame"]
        target = int(key["q1"]["answer"], 0)
        info = int(key["q2"]["answer"], 0)
        pdata, size = struct.unpack_from("<II", raw, optional + 112 + 3 * 8)
        records = [struct.unpack_from("<III", raw, at(pdata + i * 12))
                   for i in range(size // 12)]
        self.assertTrue(any(begin == target and end > begin + 0x10 and xdata == info
                            for begin, end, xdata in records))
        version, prolog, slots, frame = struct.unpack_from("<BBBB", raw, at(info))
        self.assertEqual(version & 7, 1)
        self.assertGreaterEqual(prolog, 9)
        self.assertEqual(slots, 5)
        self.assertEqual(frame & 0xF, 5)  # RBP
        self.assertEqual((frame >> 4) * 16, int(key["q4"]["answer"], 0))
        codes = [struct.unpack_from("<BB", raw, at(info) + 4 + 2 * i) for i in range(slots)]
        alloc_index = next(i for i, (_, op) in enumerate(codes) if op & 15 == 1)
        self.assertEqual(struct.unpack_from("<H", raw, at(info) + 4 + 2 * (alloc_index + 1))[0] * 8,
                         int(key["q3"]["answer"], 0))
        self.assertEqual(0x000000C00100FE70 + 0x88 + 0x10 + 8,
                         int(key["q5"]["answer"], 0))
        self.assertEqual(int(key["q6"]["answer"], 0), 0x1122334455667788)
        self.assertEqual(int(key["q7"]["answer"], 0), 0x00007FF612345678)

    def test_stream_resource_and_hidden_length_behavior(self):
        exe = ROOT / "public/artifacts/hard_stream/stream_oracle.exe"
        raw, optional, at = self.pe_reader(exe)
        key = benchmark.read_json(benchmark.KEY)["hard_resource_stream"]
        resource_rva, _ = struct.unpack_from("<II", raw, optional + 112 + 2 * 8)
        self.assertNotEqual(resource_rva, 0)

        def entry(directory_offset, wanted):
            directory = at(resource_rva) + directory_offset
            named, numbered = struct.unpack_from("<HH", raw, directory + 12)
            for index in range(named + numbered):
                identifier, value = struct.unpack_from("<II", raw, directory + 16 + index * 8)
                if identifier == wanted:
                    return value
            raise AssertionError(f"Resource ID {wanted} missing")

        rcdata = entry(0, 10) & 0x7FFFFFFF
        real_id = int(key["q3"]["answer"], 0)
        real = entry(rcdata, real_id) & 0x7FFFFFFF
        decoy = entry(rcdata, 702) & 0x7FFFFFFF
        self.assertNotEqual(real, decoy)
        _, language_entry = struct.unpack_from("<II", raw, at(resource_rva) + real + 16)
        language = language_entry & 0x7FFFFFFF
        data_rva, size = struct.unpack_from("<II", raw, at(resource_rva) + language)
        self.assertEqual(size, 128)
        self.assertNotEqual(struct.unpack_from("<Q", raw, at(data_rva))[0], STREAM_KEYS[0])
        self.assertNotIn(struct.pack("<Q", STREAM_KEYS[0]), raw)

        program = key["q1"]["answer"]
        rng = random.Random(0xAA551E)
        vectors = [b"", b"\x00", b"\xff", bytes(range(96)), bytes([0xff] * 96)]
        vectors += [rng.randbytes(rng.randrange(97)) for _ in range(20)]
        for data in vectors:
            run = subprocess.run([str(exe), data.hex() or "-"], capture_output=True, text=True)
            self.assertEqual(run.returncode, 0)
            wanted = stream_reference(data)
            self.assertEqual(int(run.stdout.strip(), 16), wanted)
            self.assertEqual(benchmark.eval_pipeline64(program, 0, 0, data), wanted)
        self.assertEqual(benchmark.stream64_points(program, program, 160), 160)
        corrupted = copy.deepcopy(program)
        corrupted["tables"]["k"][0] = "0x0"
        self.assertLess(benchmark.stream64_points(corrupted, program, 160), 160)
        invalid = subprocess.run([str(exe), "ABC"], capture_output=True, text=True)
        self.assertEqual(invalid.returncode, 2)
        nested = copy.deepcopy(program)
        nested["steps"][8]["body"].append({"op": "each", "body": [{"dst": "r0", "op": "not", "a": "r0"}]})
        with self.assertRaises(ValueError):
            benchmark.eval_pipeline64(nested, 0, 0, b"a")

    def test_repair_signatures_patch_four_pe_builds(self):
        key = benchmark.read_json(benchmark.KEY)["hard_repair_aob"]["q1"]
        expected = key["answer"]
        canonical = key["canonical_patch"]
        self.assertEqual(benchmark.patch_aob_points(canonical, expected, 120), 120)
        for version in expected["versions"]:
            raw, _, at = self.pe_reader(ROOT / version["path"])
            self.assertEqual(raw[at(int(version["length_rva"], 0))], 0x73)
            self.assertEqual(raw[at(int(version["flag_rva"], 0))], 0x75)
        broken = ROOT / expected["versions"][0]["path"]
        result = subprocess.run([str(broken), "0x100", "0x20"], capture_output=True, text=True)
        self.assertEqual(result.stdout.strip(), "REJECT")
        partial = copy.deepcopy(canonical)
        tokens = partial["sites"]["length"]["pattern"].split()
        tokens[0] = "FF"
        partial["sites"]["length"]["pattern"] = " ".join(tokens)
        self.assertEqual(benchmark.patch_aob_points(partial, expected, 120), 40)
        unsafe = copy.deepcopy(canonical)
        unsafe["sites"]["flag"]["byte"] = "90"
        self.assertEqual(benchmark.patch_aob_points(unsafe, expected, 120), 0)

    def test_tls_resource_two_pass_oracle_and_reverse_dsl(self):
        key = benchmark.read_json(benchmark.KEY)["hard_tls_stream2"]
        exe = ROOT / "public/artifacts/hard_stream2/stream2_oracle.exe"
        callback = int(key["q3"]["answer"], 0)
        self.assertIn(callback, pe_tls_callbacks(exe))
        self.assertNotIn(struct.pack("<Q", STREAM2_KEYS[0]), exe.read_bytes())
        program = key["q1"]["answer"]
        self.assertEqual([step["op"] for step in program["steps"] if "body" in step],
                         ["each", "each_reverse"])
        rng = random.Random(0x20271009)
        vectors = [b"", b"\x00", b"\xff", bytes(range(96)), bytes([0xff] * 96)]
        vectors += [rng.randbytes(rng.randrange(97)) for _ in range(16)]
        for data in vectors:
            process = subprocess.run([str(exe), data.hex() or "-"], capture_output=True, text=True)
            wanted = stream2_reference(data)
            self.assertEqual(process.returncode, 0)
            self.assertEqual(int(process.stdout.strip(), 16), wanted)
            self.assertEqual(benchmark.eval_pipeline64(program, 0, 0, data), wanted)
        changed = copy.deepcopy(program)
        changed["steps"][9]["op"] = "each"
        self.assertLess(benchmark.stream64_points(changed, program, 300), 300)
        alias = copy.deepcopy(program)
        for step in alias["steps"]:
            for item in step.get("body", [step]):
                if item.get("op") in {"rol", "ror", "shl", "shr"}:
                    item["b"] = item.pop("bits")
        self.assertEqual(benchmark.stream64_points(alias, program, 300), 300)

    def test_real_minidump_records_pointer_truncation(self):
        key = benchmark.read_json(benchmark.KEY)["hard_crash_dump"]
        dump = ROOT / "public/artifacts/hard_dump/fault.dmp"
        exe = ROOT / "public/artifacts/hard_dump/dump_probe.exe"
        parsed = parse_dump(dump)
        full = int(key["q5"]["answer"], 0)
        encoded = int(key["q6"]["answer"], 0)
        self.assertEqual(parsed["code"], int(key["q1"]["answer"], 0))
        self.assertEqual(parsed["rva"], int(key["q2"]["answer"], 0))
        self.assertEqual(parsed["fault"], int(key["q3"]["answer"], 0))
        self.assertEqual(parsed["access"], 0)
        self.assertEqual(parsed["fault"], (full & 0xFFFFFFFF) + 3)
        self.assertEqual(encoded ^ DUMP_COOKIE, full)
        self.assertIn(struct.pack("<Q", encoded), parsed["raw"])
        self.assertGreaterEqual(parsed["thread_count"], 1)
        self.assertEqual(exe.read_bytes()[:2], b"MZ")


if __name__ == "__main__":
    unittest.main()
