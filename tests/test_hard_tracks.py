import hashlib
import json
import subprocess
import unittest
from pathlib import Path

from agentre_track import UPSTREAM, audited_ground_truth, parse_answer as parse_agentre
from protected_vm_bench import MANIFEST, ROOT, SOURCE, generate, pack, parse_answer as parse_vm, unpack


class HardTrackTests(unittest.TestCase):
    def test_pack_roundtrip_with_references_and_literals(self):
        data = b"ABCD" * 60 + bytes(range(128)) + b"ABCD" * 30
        packed = pack(data)
        self.assertLess(len(packed), len(data))
        self.assertEqual(unpack(packed), data)

    def test_generated_protected_variants_change_payload(self):
        one = generate(12345)
        two = generate(12346)
        self.assertEqual(unpack(one[2]), one[1])
        self.assertNotEqual(hashlib.sha256(one[1]).digest(), hashlib.sha256(two[1]).digest())
        self.assertEqual(len(one[0]), 24)

    def test_compiled_pe_contains_cipher_and_behaves_as_oracle(self):
        if not MANIFEST.is_file():
            self.skipTest("protected VM artifacts have not been built")
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
        seed = manifest["generator_seed"]
        for number, case in enumerate(manifest["cases"]):
            case_seed = int.from_bytes(hashlib.sha256(f"{seed}:{number}".encode()).digest()[:8], "little")
            secret, plain, packed, cipher, _ = generate(case_seed)
            binary = ROOT / case["exe"]
            data = binary.read_bytes()
            self.assertEqual(hashlib.sha256(data).hexdigest(), case["exe_sha256"])
            self.assertLess(len(packed), len(plain))
            self.assertIn(cipher, data)
            self.assertNotIn(plain, data)
            self.assertNotIn(secret.encode(), data)
            self.assertEqual(subprocess.run([str(binary), secret], capture_output=True, timeout=5).returncode, 0)
            self.assertNotEqual(subprocess.run([str(binary), "A" * 24], capture_output=True, timeout=5).returncode, 0)

    def test_upx_wrapped_pe_preserves_oracle(self):
        upx_manifest = SOURCE / "upx_manifest.json"
        if not upx_manifest.is_file() or not MANIFEST.is_file():
            self.skipTest("UPX artifacts have not been built")
        original = {x["case_id"]: x for x in json.loads(MANIFEST.read_text(encoding="utf-8"))["cases"]}
        packed = json.loads(upx_manifest.read_text(encoding="utf-8"))["cases"]
        self.assertEqual(set(original), {x["case_id"] for x in packed})
        for case in packed:
            binary = ROOT / case["exe"]
            data = binary.read_bytes()
            self.assertIn(b"UPX!", data)
            self.assertLess(len(data), (ROOT / original[case["case_id"]]["exe"]).stat().st_size)
            self.assertEqual(hashlib.sha256(data).hexdigest(), case["sha256"])
            self.assertEqual(subprocess.run([str(binary), original[case["case_id"]]["secret"]],
                                            capture_output=True, timeout=10).returncode, 0)

    def test_answer_parser_requires_correct_case(self):
        with self.assertRaises(ValueError):
            parse_agentre('{"case_id":"wrong","answer":{}}', "target")
        with self.assertRaises(ValueError):
            parse_vm('{"case_id":"wrong","code":"x"}', "target")
        self.assertEqual(parse_agentre('{"case_id":"target","answer":{"techniques":[]}}', "target"),
                         {"techniques": []})

    def test_agentre_c2_audit_uses_frozen_binary_bytes(self):
        path = UPSTREAM / "version3" / "ground_truths" / "windows_level23_WannaCryWorm.json"
        if not path.is_file():
            self.skipTest("AgentRE-Bench is not checked out")
        original = json.loads(path.read_text(encoding="utf-8"))
        fixed = audited_ground_truth({"upstream_task": "v3_l23_s"}, original)
        self.assertEqual(original["decoded_c2"], "192.0.2.100:8443")
        self.assertEqual(fixed["decoded_c2"], "255.255.255.255:8443")
        self.assertEqual(fixed["decoded_strings"]["c2_ip_hex"], "4d6e70423368412403276d7621")
        self.assertEqual(original["decoded_strings"]["c2_ip"], "192.0.2.100")


if __name__ == "__main__":
    unittest.main()
