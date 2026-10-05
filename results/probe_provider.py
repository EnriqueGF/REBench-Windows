"""Small read-only availability probe for the configured OpenCode provider."""
import json
import pathlib
import time
import urllib.error
import urllib.request
import winreg

config = json.loads((pathlib.Path.home() / ".config/opencode/opencode.json").read_text(encoding="utf-8"))
provider = config["provider"]["explabs"]
model = "glm-5.3-flash-abliterated"
key = winreg.QueryValueEx(winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment"), "EXPLABS_API_KEY")[0]
url = provider["options"]["baseURL"].rstrip("/") + "/chat/completions"
body = json.dumps({"model": model, "messages": [{"role": "user", "content": "Responde solamente OK."}], "max_tokens": 16}).encode("utf-8")
request = urllib.request.Request(url, data=body, headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
start = time.monotonic()
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        payload = json.loads(response.read())
        print("HTTP", response.status, "seconds", round(time.monotonic() - start, 2), "choices", len(payload.get("choices", [])))
except urllib.error.HTTPError as exc:
    try:
        error = json.loads(exc.read()).get("error", {})
        kind = error.get("type") or error.get("code")
        message = str(error.get("message", ""))[:180].replace(key, "[REDACTED]")
    except Exception:
        kind, message = None, ""
    print("HTTP", exc.code, "seconds", round(time.monotonic() - start, 2),
          "retry_after", exc.headers.get("Retry-After"), "kind", kind, "message", message)
except Exception as exc:
    print("ERROR", type(exc).__name__, "seconds", round(time.monotonic() - start, 2))
