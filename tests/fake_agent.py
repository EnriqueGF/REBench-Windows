import json
import sys

prompt = sys.argv[-1]
case_id = next(line.split(":", 1)[0].split()[-1] for line in prompt.splitlines() if line.startswith("CASO "))
print(json.dumps({"case_id": case_id, "answers": {"q1": "0x180001234", "q2": "B", "q3": "0x40000000"}, "reasoning": "fixture"}))
