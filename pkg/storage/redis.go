package storage

import (
	"context"
	"fmt"
	"log"

	"github.com/redis/go-redis/v9" // Redis 클라이언트 임포트
)

func NewRedisClient(addr, password string) (*redis.Client, error) {
	rdb := redis.NewClient(&redis.Options{
		Addr:     addr,
		Password: password,
	})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis 연결 실패 (%s): %v\n", addr, err)
	}
	fmt.Printf("Redis 연결 성공: %s\n", addr)

	return rdb, nil
}
