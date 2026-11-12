"""SSRF 방어: 사용자가 준 URL이 내부망/로컬을 가리키지 못하게 막는다."""
import ipaddress
import os
import socket
from urllib.parse import urlparse


class UnsafeURL(ValueError):
    """검사하면 안 되는 URL일 때 발생."""


def _is_blocked_ip(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local   # 169.254.x.x (클라우드 메타데이터 주소 포함)
        or addr.is_reserved
        or addr.is_multicast
        or addr.is_unspecified
    )


def validate_url(url: str) -> str:
    """안전한 URL이면 그대로 반환, 아니면 UnsafeURL 발생."""
    parsed = urlparse(url)

    if parsed.scheme not in ("http", "https"):
        raise UnsafeURL("http:// 또는 https:// 주소만 검사할 수 있습니다.")
    if not parsed.hostname:
        raise UnsafeURL("호스트 이름이 없는 URL입니다.")
    if parsed.username or parsed.password:
        raise UnsafeURL("URL에 계정 정보를 포함할 수 없습니다.")

    # 내 로컬 서버를 테스트하고 싶을 때만 ALLOW_PRIVATE=1 로 허용
    if os.environ.get("ALLOW_PRIVATE") == "1":
        return url

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise UnsafeURL("도메인을 찾을 수 없습니다.")

    for info in infos:
        ip = info[4][0]
        if _is_blocked_ip(ip):
            raise UnsafeURL("내부망/로컬 주소는 검사할 수 없습니다.")
    return url
