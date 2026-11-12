"""fetch 결과를 받아 모든 검사를 실행하고 점수/등급을 계산한다."""
from . import headers as h
from .cookies import check_cookies
from .fetcher import fetch


def grade_for(percent: float) -> str:
    for threshold, grade in ((90, "A"), (80, "B"), (65, "C"), (50, "D")):
        if percent >= threshold:
            return grade
    return "F"


def run_checks(headers: dict, set_cookies: list, is_https: bool) -> list:
    results = [
        h.check_hsts(headers, is_https),
        h.check_csp(headers),
        h.check_frame_protection(headers),
        h.check_nosniff(headers),
        h.check_referrer_policy(headers),
        h.check_permissions_policy(headers),
        h.check_info_leak(headers),
    ]
    cookie_result = check_cookies(set_cookies, is_https)
    if cookie_result:
        results.append(cookie_result)
    return results


def summarize(results: list) -> dict:
    total = sum(r["points"] for r in results)
    max_total = sum(r["max"] for r in results)
    percent = round(total / max_total * 100, 1) if max_total else 0
    return {"score": total, "max_score": max_total,
            "percent": percent, "grade": grade_for(percent)}


def analyze(url: str) -> dict:
    fetched = fetch(url)
    is_https = fetched.final_url.lower().startswith("https://")
    results = run_checks(fetched.headers, fetched.set_cookies, is_https)
    return {
        "url": url,
        "final_url": fetched.final_url,
        "status_code": fetched.status,
        "redirects": fetched.redirects,
        **summarize(results),
        "checks": results,
    }
