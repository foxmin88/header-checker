"""Set-Cookie 속성 검사: Secure / HttpOnly / SameSite."""


def parse_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name = parts[0].split("=", 1)[0]
    attrs = {}
    for p in parts[1:]:
        key, _, val = p.partition("=")
        attrs[key.strip().lower()] = val.strip().lower()
    return {"name": name, "attrs": attrs}


def check_cookies(set_cookies, is_https):
    """쿠키가 없으면 None(점수 계산에서 제외)을 반환한다."""
    if not set_cookies:
        return None

    issues = []
    for raw in set_cookies:
        cookie = parse_cookie(raw)
        attrs, name = cookie["attrs"], cookie["name"]
        if "secure" not in attrs and is_https:
            issues.append(f"{name}: Secure 없음")
        if "httponly" not in attrs:
            issues.append(f"{name}: HttpOnly 없음")
        if "samesite" not in attrs:
            issues.append(f"{name}: SameSite 없음")
        elif attrs["samesite"] == "none" and "secure" not in attrs:
            issues.append(f"{name}: SameSite=None 인데 Secure 없음")

    title = "쿠키 보안 속성"
    if not issues:
        return {"id": "cookies", "name": title, "status": "pass",
                "points": 10, "max": 10,
                "message": f"쿠키 {len(set_cookies)}개 모두 안전하게 설정되어 있습니다.", "fix": ""}
    points = max(0, 10 - 2 * len(issues))
    return {"id": "cookies", "name": title,
            "status": "fail" if points <= 4 else "warn",
            "points": points, "max": 10,
            "message": "; ".join(issues),
            "fix": "Set-Cookie: ...; Secure; HttpOnly; SameSite=Lax"}
