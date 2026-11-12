"""터미널에서 바로 점검:  python cli.py https://example.com"""
import json
import sys

from checker import analyze
from checker.ssrf import UnsafeURL

ICON = {"pass": "[ OK ]", "warn": "[WARN]", "fail": "[FAIL]"}


def main():
    if len(sys.argv) < 2:
        print("사용법: python cli.py <url> [--json]")
        sys.exit(1)

    url = sys.argv[1]
    if "://" not in url:
        url = "https://" + url

    try:
        report = analyze(url)
    except UnsafeURL as e:
        print(f"검사할 수 없는 URL: {e}")
        sys.exit(2)
    except Exception as e:
        print(f"요청 실패: {e}")
        sys.exit(3)

    if "--json" in sys.argv:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return

    print(f"\n{report['final_url']}  (HTTP {report['status_code']})")
    print(f"등급 {report['grade']}  |  {report['score']}/{report['max_score']}점 ({report['percent']}%)\n")
    for c in report["checks"]:
        print(f"{ICON[c['status']]} {c['name']}  ({c['points']}/{c['max']})")
        print(f"       {c['message']}")
        if c["status"] != "pass" and c["fix"]:
            print(f"       → {c['fix']}")
    print()


if __name__ == "__main__":
    main()
