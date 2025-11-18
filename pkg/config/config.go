package config

import (
	"log"
	"os"
)

// !!! 중요: libc.so.6의 실제 경로는 시스템마다 다를 수 있습니다. 걍 이미지에 넣어버리겠음
const LibcPath = "./libc.so.6"

// LoadRedisAddr는 환경 변수에서 Redis 주소를 로드합니다.
func LoadRedisAddr() string {
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379" // 환경 변수가 없으면 localhost를 기본값으로 사용
		log.Printf("[정보] REDIS_ADDR 환경 변수가 설정되지 않았습니다. 기본값(localhost:6379)으로 연결 시도...")
	}
	return redisAddr
}

// [신규] LoadRedisPassword는 환경 변수에서 Redis 비밀번호를 로드합니다.
func LoadRedisPassword() string {
	// Job 매니페스트에서 Secret을 통해 주입될 것입니다.
	return os.Getenv("REDIS_PASSWORD")
}
