# go.mod 기준 1.24.3 사용
FROM golang:1.24.3-alpine AS builder

WORKDIR /src

# 의존성 모듈 먼저 다운로드 (레이어 캐싱 활용)
COPY go.mod go.sum ./
RUN go mod download

# 소스 코드 복사
COPY . .

# [수정] CGO 빌드 및 Capstone 의존성 설치
RUN apk add --no-cache gcc musl-dev capstone-dev

# main.go를 기반으로 바이너리 빌드
# [수정] CGO_ENABLED=1: CGO 기반 패키지(Capstone 등) 빌드 허용
RUN CGO_ENABLED=1 go build -o /analyzer ./cmd/static-analyzer/main.go


# --- 실행 단계 ---
FROM alpine:latest

# [수정] 런타임 의존성 설치 (syscall_filter.go가 'man' 명령어 사용)
# 'man' 명령어를 제공하는 mandoc, man-pages 패키지 설치
RUN apk update && apk add --no-cache mandoc man-pages

# 빌드 단계에서 생성된 바이너리 복사
COPY --from=builder /analyzer /analyzer

# [수정] 프로젝트 루트(빌드 컨텍스트)의 libc.so.6 파일을 이미지 루트(/)로 복사
# Go 코드에서 "/libc.so.6" 경로로 접근 가능
COPY libc.so.6 /

# 분석기 실행
# <분석할_ELF_파일_경로>는 Kubernetes Job에서 인자(args)로 전달
ENTRYPOINT ["/analyzer"]