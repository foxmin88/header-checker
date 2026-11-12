"""URL에 요청을 보내 응답 헤더만 가져온다. 리다이렉트도 매 단계마다 SSRF 검사."""
from urllib.parse import urljoin

import requests

from .ssrf import UnsafeURL, validate_url

MAX_REDIRECTS = 3
TIMEOUT = 5
USER_AGENT = "header-checker/0.1 (+security header audit)"


class FetchResult:
    def __init__(self, final_url, status, headers, set_cookies, redirects):
        self.final_url = final_url
        self.status = status
        self.headers = headers          # 키는 소문자
        self.set_cookies = set_cookies  # Set-Cookie 원문 리스트
        self.redirects = redirects      # 거쳐온 URL 리스트


def fetch(url: str) -> FetchResult:
    current = validate_url(url)
    chain = [current]

    for _ in range(MAX_REDIRECTS + 1):
        resp = requests.get(
            current,
            headers={"User-Agent": USER_AGENT},
            timeout=TIMEOUT,
            allow_redirects=False,  # 직접 따라가며 검증
            stream=True,            # 본문은 읽지 않는다
        )
        try:
            location = resp.headers.get("Location")
            if resp.is_redirect and location:
                current = validate_url(urljoin(current, location))
                chain.append(current)
                continue

            headers = {k.lower(): v for k, v in resp.headers.items()}
            raw = resp.raw.headers
            cookies = raw.getlist("Set-Cookie") if hasattr(raw, "getlist") else []
            return FetchResult(current, resp.status_code, headers, cookies, chain)
        finally:
            resp.close()

    raise UnsafeURL("리다이렉트가 너무 많습니다.")
