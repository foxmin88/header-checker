"""보안 헤더 검사 규칙. 각 함수는 결과 dict 하나를 반환한다.

status: pass(통과) / warn(개선 권장) / fail(미설정 또는 위험)
"""


def _result(id_, name, status, points, max_points, message, fix=""):
    return {
        "id": id_, "name": name, "status": status,
        "points": points, "max": max_points,
        "message": message, "fix": fix,
    }


def check_hsts(headers, is_https):
    name = "Strict-Transport-Security (HSTS)"
    if not is_https:
        return _result("hsts", name, "fail", 0, 15,
                       "HTTPS를 쓰지 않아 HSTS를 적용할 수 없습니다.",
                       "사이트 전체를 HTTPS로 전환하세요.")
    value = headers.get("strict-transport-security")
    if not value:
        return _result("hsts", name, "fail", 0, 15, "HSTS 헤더가 없습니다.",
                       "Strict-Transport-Security: max-age=31536000; includeSubDomains")
    max_age = 0
    for part in value.split(";"):
        part = part.strip().lower()
        if part.startswith("max-age="):
            try:
                max_age = int(part.split("=", 1)[1])
            except ValueError:
                pass
    if max_age < 15552000:  # 180일
        return _result("hsts", name, "warn", 8, 15,
                       f"max-age가 너무 짧습니다 ({max_age}초).",
                       "max-age를 최소 15552000(180일), 권장 31536000(1년)으로 늘리세요.")
    if "includesubdomains" not in value.lower():
        return _result("hsts", name, "warn", 12, 15,
                       "includeSubDomains가 없어 서브도메인은 보호되지 않습니다.",
                       "includeSubDomains 옵션을 추가하세요.")
    return _result("hsts", name, "pass", 15, 15, "HSTS가 잘 설정되어 있습니다.")


def check_csp(headers):
    name = "Content-Security-Policy (CSP)"
    value = headers.get("content-security-policy")
    if not value:
        return _result("csp", name, "fail", 0, 25,
                       "CSP 헤더가 없습니다. XSS 피해를 줄여주는 가장 중요한 헤더입니다.",
                       "Content-Security-Policy: default-src 'self'")
    lowered = value.lower()
    problems = []
    if "'unsafe-inline'" in lowered:
        problems.append("'unsafe-inline'")
    if "'unsafe-eval'" in lowered:
        problems.append("'unsafe-eval'")
    if " * " in f" {lowered} " or "default-src *" in lowered or "script-src *" in lowered:
        problems.append("와일드카드(*)")
    if problems:
        return _result("csp", name, "warn", 15, 25,
                       "CSP가 있지만 약화시키는 설정이 있습니다: " + ", ".join(problems),
                       "unsafe-inline/eval 대신 nonce 또는 hash를 사용하세요.")
    return _result("csp", name, "pass", 25, 25, "CSP가 설정되어 있습니다.")


def check_frame_protection(headers):
    name = "클릭재킹 방어 (X-Frame-Options / frame-ancestors)"
    csp = headers.get("content-security-policy", "").lower()
    xfo = headers.get("x-frame-options", "").strip().lower()
    if "frame-ancestors" in csp or xfo in ("deny", "sameorigin"):
        return _result("frame", name, "pass", 10, 10, "다른 사이트의 iframe 삽입이 제한됩니다.")
    return _result("frame", name, "fail", 0, 10,
                   "클릭재킹 방어 설정이 없습니다.",
                   "X-Frame-Options: DENY 또는 CSP의 frame-ancestors 'none' 을 설정하세요.")


def check_nosniff(headers):
    name = "X-Content-Type-Options"
    if headers.get("x-content-type-options", "").strip().lower() == "nosniff":
        return _result("nosniff", name, "pass", 10, 10, "MIME 스니핑이 차단됩니다.")
    return _result("nosniff", name, "fail", 0, 10, "nosniff 설정이 없습니다.",
                   "X-Content-Type-Options: nosniff")


def check_referrer_policy(headers):
    name = "Referrer-Policy"
    value = headers.get("referrer-policy", "").strip().lower()
    if not value:
        return _result("referrer", name, "fail", 0, 5, "Referrer-Policy가 없습니다.",
                       "Referrer-Policy: strict-origin-when-cross-origin")
    if value in ("unsafe-url", "no-referrer-when-downgrade"):
        return _result("referrer", name, "warn", 2, 5,
                       f"'{value}'는 전체 URL을 외부로 노출할 수 있습니다.",
                       "strict-origin-when-cross-origin 또는 no-referrer를 사용하세요.")
    return _result("referrer", name, "pass", 5, 5, "Referrer-Policy가 설정되어 있습니다.")


def check_permissions_policy(headers):
    name = "Permissions-Policy"
    if headers.get("permissions-policy") or headers.get("feature-policy"):
        return _result("permissions", name, "pass", 5, 5, "브라우저 기능 사용 범위가 제한됩니다.")
    return _result("permissions", name, "warn", 0, 5,
                   "Permissions-Policy가 없습니다.",
                   "Permissions-Policy: camera=(), microphone=(), geolocation=()")


def check_info_leak(headers):
    name = "서버 정보 노출"
    leaks = []
    for key in ("server", "x-powered-by", "x-aspnet-version"):
        value = headers.get(key)
        # 버전 숫자까지 노출되는 경우만 문제로 본다 (예: nginx/1.18.0)
        if value and any(ch.isdigit() for ch in value):
            leaks.append(f"{key}: {value}")
    if leaks:
        return _result("leak", name, "warn", 0, 5,
                       "소프트웨어 버전이 노출됩니다: " + ", ".join(leaks),
                       "Server / X-Powered-By 헤더에서 버전 정보를 제거하세요.")
    return _result("leak", name, "pass", 5, 5, "버전 정보가 노출되지 않습니다.")
