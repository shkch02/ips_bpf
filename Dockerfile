# [수정] Go 1.24.3 + Alpine 3.16 (Capstone v4) 환경을 수동으로 구성
FROM alpine:3.16 AS builder

# BuildKit이 제공하는 아키텍처(amd64, arm64 등)에 맞춰 Go 설치
ARG TARGETARCH
ENV GOLANG_VERSION=1.24.3
ENV GOLANG_ARCH=${TARGETARCH:-amd64}
ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOROOT=/usr/local/go

# Go 1.24.3 수동 설치
RUN apk add --no-cache curl \
    && curl -fsSL "https://go.dev/dl/go${GOLANG_VERSION}.linux-${GOLANG_ARCH}.tar.gz" -o go.tar.gz \
    && tar -C /usr/local -xzf go.tar.gz \
    && rm go.tar.gz \
    && go version

# CGO 빌드 의존성 (Capstone v4)
RUN apk add --no-cache gcc musl-dev capstone-dev pkgconf

WORKDIR /src

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

# [유지] 실행 환경은 Capstone v4가 있는 alpine:3.16으로 고정
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