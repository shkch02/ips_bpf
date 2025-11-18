# [수정] Go 1.24.3 + Debian Slim 기반 사용 (man page 호환성 확보)
FROM golang:1.24.3-bookworm AS builder

# BuildKit이 제공하는 아키텍처(amd64, arm64 등)에 맞춰 Go 설치
ARG TARGETARCH
# Alpine 관련 환경 변수 제거
# ENV GOLANG_VERSION=1.24.3
# ENV GOLANG_ARCH=${TARGETARCH:-amd64}
# ENV PATH="/usr/local/go/bin:${PATH}"
# ENV GOROOT=/usr/local/go

# CGO 및 man 페이지 의존성 설치 (Debian/Ubuntu 계열 명령어 사용)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libc6-dev \
    libcapstone5-dev \
    pkg-config \
    manpages-dev \
    man-db \
    && rm -rf /var/lib/apt/lists/*
    
WORKDIR /src

# 의존성 모듈 먼저 다운로드
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# main.go를 기반으로 바이너리 빌드 (CGO_ENABLED=1)
# pkg-config로 Capstone 플래그 설정
RUN CGO_ENABLED=1 \
    CGO_CFLAGS="$(pkg-config --cflags capstone)" \
    CGO_LDFLAGS="$(pkg-config --libs capstone)" \
    go build -o /analyzer ./cmd/static-analyzer/main.go


# --- 실행 단계 ---

# [수정] 실행 환경도 Debian Slim으로 변경
FROM debian:stable-slim

# 런타임 의존성 설치
# libcapstone4 및 man 실행에 필요한 패키지 설치
RUN apt-get update && apt-get install -y --no-install-recommends \
    mandoc \
    man-db \
    libcapstone5 \
    && rm -rf /var/lib/apt/lists/*

# 빌드 단계에서 생성된 바이너리 복사
COPY --from=builder /analyzer /analyzer

# libc.so.6 파일 복사 (프로젝트 루트에서 복사)
# Alpine에서 Debian으로 변경했으므로, 이 libc.so.6 파일의 호환성 문제가 있을 수 있으나, 일단 유지
COPY libc.so.6 /

# 분석기 실행
ENTRYPOINT ["/analyzer"]