# header-checker

웹사이트의 **보안 헤더와 쿠키 설정**을 점검해서 점수(A~F)와 개선 방법을 알려주는 도구입니다.
웹 화면, REST API, CLI 세 가지 방식으로 쓸 수 있습니다.

## 주요 기능

- 보안 헤더 7종 검사: HSTS, CSP, 클릭재킹 방어, nosniff, Referrer-Policy, Permissions-Policy, 서버 정보 노출
- `Set-Cookie` 속성 검사: Secure / HttpOnly / SameSite
- 항목별 가중치 점수와 A~F 등급, 항목마다 **고치는 방법** 제시
- **SSRF 방어**: 내부망/로컬/메타데이터(169.254.x.x) 주소 차단, 리다이렉트도 단계마다 재검증
- IP별 요청 제한 (분당 10회)

## 실행

```bash
pip install -r requirements.txt

python app.py                          # 웹: http://127.0.0.1:5000
python cli.py https://example.com      # CLI
python cli.py example.com --json       # JSON 출력
curl "http://127.0.0.1:5000/check?url=https://example.com"   # API
```

내 로컬 서버를 검사하고 싶을 때만 `ALLOW_PRIVATE=1 python cli.py http://127.0.0.1:8000` 처럼 실행합니다.

## 테스트

```bash
python -m unittest discover -s tests -t . -v
```

## 구조

```
header-checker/
├── app.py            # Flask 서버 (/, /check)
├── cli.py            # 터미널 도구
├── checker/
│   ├── ssrf.py       # URL 검증 (SSRF 방어)
│   ├── fetcher.py    # 헤더 수집, 리다이렉트 처리
│   ├── headers.py    # 헤더별 검사 규칙
│   ├── cookies.py    # 쿠키 검사
│   └── analyzer.py   # 점수/등급 계산
├── static/index.html # 웹 화면
└── tests/
```

## 점수 기준

| 항목 | 배점 |
|---|---|
| CSP | 25 |
| HSTS | 15 |
| 클릭재킹 방어 | 10 |
| X-Content-Type-Options | 10 |
| 쿠키 속성 (쿠키가 있을 때만) | 10 |
| Referrer-Policy / Permissions-Policy / 정보 노출 | 각 5 |

90%↑ A, 80%↑ B, 65%↑ C, 50%↑ D, 그 미만 F

## 진행 상황

- [x] 헤더 검사 규칙
- [x] 쿠키 검사
- [x] SSRF 방어
- [x] 웹 화면 / API / CLI
- [x] 단위 테스트
- [ ] DNS rebinding 방어 (검증한 IP로 직접 연결하도록 고정)
- [ ] CSP 세부 분석 (디렉티브별 점검)
- [ ] TLS 버전/인증서 만료일 점검
- [ ] 결과 JSON/PDF 내보내기
- [ ] Docker 배포
