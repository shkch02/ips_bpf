# go.mod 기준 1.24.3 사용
FROM golang:1.24.3-alpine AS builder

WORKDIR /src

# [수정] CGO 빌드 의존성: gcc, musl-dev, capstone-dev, 그리고 pkgconf 추가
# pkgconf는 pkg-config를 제공하여 C 라이브러리 플래그를 자동으로 찾기 위해 필요합니다.
RUN apk add --no-cache gcc musl-dev capstone-dev pkgconf

# 의존성 모듈 먼저 다운로드 (레이어 캐싱 활용)
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# main.go를 기반으로 바이너리 빌드
# [수정] CGO_ENABLED=1로 빌드
# pkg-config를 사용하여 Capstone 라이브러리의 C 플래그와 링커 플래그를 자동으로 설정
RUN CGO_ENABLED=1 \
    CGO_CFLAGS="$(pkg-config --cflags capstone)" \
    CGO_LDFLAGS="$(pkg-config --libs capstone)" \
    go build -o /analyzer ./cmd/static-analyzer/main.go


# --- 실행 단계 ---
FROM alpine:latest

# [수정] 런타임 의존성
# 1. 'man' 명령어 (mandoc, man-pages)
# 2. 'capstone' C 라이브러리 (capstone 패키지 - 'capstone-dev'가 아님)
RUN apk update && apk add --no-cache mandoc man-pages capstone

# 빌드 단계에서 생성된 바이너리 복사
COPY --from=builder /analyzer /analyzer

# [수정] 프로젝트 루트(빌드 컨텍스트)의 libc.so.6 파일을 이미지 루트(/)로 복사
COPY libc.so.6 /

# 분석기 실행
ENTRYPOINT ["/analyzer"]