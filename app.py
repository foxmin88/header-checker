"""웹 보안 헤더 점검기 서버.

실행:  python app.py        → http://127.0.0.1:5000
API :  GET /check?url=https://example.com
"""
import time
from collections import defaultdict, deque

import requests
from flask import Flask, jsonify, request, send_from_directory

from checker import analyze
from checker.ssrf import UnsafeURL

app = Flask(__name__, static_folder="static", static_url_path="/static")

# --- 아주 단순한 IP별 요청 제한 (분당 10회, 메모리 기반) ---
RATE_LIMIT = 10
WINDOW_SECONDS = 60
_hits = defaultdict(deque)


def too_many_requests(ip: str) -> bool:
    now = time.time()
    q = _hits[ip]
    while q and now - q[0] > WINDOW_SECONDS:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        return True
    q.append(now)
    return False


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/check")
def check():
    if too_many_requests(request.remote_addr or "unknown"):
        return jsonify(error="요청이 너무 많습니다. 잠시 후 다시 시도하세요."), 429

    url = (request.args.get("url") or "").strip()
    if not url:
        return jsonify(error="url 파라미터가 필요합니다. 예: /check?url=https://example.com"), 400
    if "://" not in url:
        url = "https://" + url

    try:
        return jsonify(analyze(url))
    except UnsafeURL as e:
        return jsonify(error=str(e)), 400
    except requests.exceptions.SSLError:
        return jsonify(error="TLS 인증서 오류로 연결할 수 없습니다."), 502
    except requests.exceptions.RequestException:
        return jsonify(error="사이트에 연결할 수 없습니다."), 502


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
