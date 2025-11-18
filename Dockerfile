# [수정] go.mod 기준 1.24.3, Alpine 3.16 기반 사용
# Alpine 3.16은 Capstone v4.0.2를 제공하여 gapstone v4.0.1과 호환됩니다.
FROM golang:1.24.3-alpine3.16 AS builder

WORKDIR /src

# CGO 빌드 의존성 (gcc, musl-dev, capstone-dev, pkgconf)
# alpine3.16의 capstone-dev는 v4.0.2입니다.
RUN apk add --no-cache gcc musl-dev capstone-dev pkgconf

# 의존성 모듈 먼저 다운로드
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# main.go를 기반으로 바이너리 빌드 (CGO_ENABLED=1)
# pkg-config로 Capstone v4 플래그 설정
RUN CGO_ENABLED=1 \
    CGO_CFLAGS="$(pkg-config --cflags capstone)" \
    CGO_LDFLAGS="$(pkg-config --libs capstone)" \
    go build -o /analyzer ./cmd/static-analyzer/main.go


# --- 실행 단계 ---

# [수정] 실행 환경도 Capstone v4가 있는 alpine:3.16으로 고정
FROM alpine:3.16

# 런타임 의존성 설치
# 1. 'man' 명령어 (mandoc, man-pages)
# 2. 'capstone' C 라이브러리 v4 (capstone 패키지)
RUN apk update && apk add --no-cache mandoc man-pages capstone

# 빌드 단계에서 생성된 바이너리 복사
COPY --from=builder /analyzer /analyzer

# libc.so.6 파일 복사
COPY libc.so.6 /

# 분석기 실행
ENTRYPOINT ["/analyzer"]