

#go.mod 기준 1.24.3 사용

FROM golang:1.24.3-alpine AS builder

WORKDIR /src

#의존성 모듈 먼저 다운로드 (레이어 캐싱 활용)

COPY go.mod go.sum ./
RUN go mod download

#소스 코드 복사

COPY . .

#main.go를 기반으로 바이너리 빌드

#CGO_ENABLED=0: 정적 링크 (Alpine 리눅스에서 권장)

RUN CGO_ENABLED=0 go build -o /analyzer ./cmd/static-analyzer/main.go



FROM alpine:latest

#런타임 의존성 설치 (매우 중요!)

#syscall_filter.go가 'man' 명령어를 사용함

RUN apk add --no-cache man man-pages

#빌드 단계에서 생성된 바이너리 복사

COPY --from=builder /analyzer /analyzer

#[수정] 프로젝트 루트에 있는 libc.so.6 파일을 이미지 루트 디렉토리로 복사

#Go 코드에서 "./libc.so.6"로 접근할 수 있도록 /에 복사합니다.

COPY libc.so.6 /

#분석기 실행

#<분석할_ELF_파일_경로>는 Kubernetes Job에서 인자(args)로 전달

ENTRYPOINT ["/analyzer"]