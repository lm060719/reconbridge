"""Exercise the real apkanalyzer wrapper against the Tracer APK built by CI."""
import argparse
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "pc"))
from reconbridge_mcp.device_tools import analyze_apk_metadata

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("apk")
    args = parser.parse_args()
    for section in ("summary", "manifest", "permissions", "files"):
        result = analyze_apk_metadata(args.apk, section)
        print(json.dumps(result, ensure_ascii=False), flush=True)
        assert result["ok"], result
        if section in {"summary", "manifest"}: assert "com.reconbridge.tracer" in result["output_tail"]
        if section == "files": assert "AndroidManifest.xml" in result["output_tail"]
