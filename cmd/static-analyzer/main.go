// cmd/static-analyzer/main.go
package main

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer"
	"ips_bpf/static-analyzer/pkg/config"    // [신규]
	"ips_bpf/static-analyzer/pkg/processor" // [신규]
	"log"
	"os"
	"strings"

	"github.com/redis/go-redis/v9" // Redis 클라이언트 임포트
)

func main() {
	// 프로그램 인자 존재하는지 확인 (프로그램 이름 + 파일 경로)하고 없으면 사용법 출력
	if len(os.Args) < 2 {
		fmt.Println("사용법: go run cmd/static-analyzer/main.go <ELF 파일 경로>")
		os.Exit(1)
	}

	// [이동] Redis 초기화 로직 (주석 처리됨)

	// [수정] config.LoadRedisAddr() 호출
	redisAddr := config.LoadRedisAddr()
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})
	ctx := context.Background()
	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("Redis 연결 실패 (%s): %v\n", redisAddr, err)
	}
	fmt.Printf("Redis 연결 성공: %s\n", redisAddr)

	// 첫 번째 인자를 파일 경로로 사용
	filePath := os.Args[1]
	fmt.Printf("분석 대상 파일: %s\n", filePath)
	fmt.Println("----------------------------------------")

	// --- 1. 대상 ELF 분석기 초기화 ---
	elfAnalyzer, err := analyzer.New(filePath)
	if err != nil {
		log.Fatalf("대상 ELF 분석기 생성 오류: %v", err)
	}
	defer elfAnalyzer.Close()

	// --- 2. Libc 분석기 초기화 ---
	// [수정] config.LibcPath 사용
	fmt.Printf("Glibc 라이브러리 분석 중: %s\n", config.LibcPath)
	libcAnalyzer, err := analyzer.New(config.LibcPath)
	if err != nil {
		log.Fatalf("Libc 분석기 생성 오류: %v", err)
	}
	defer libcAnalyzer.Close()

	// --- 3. 대상 ELF에서 동적 심볼 추출 ---
	symbols, err := elfAnalyzer.ExtractDynamicSymbols()
	if err != nil {
		if _, ok := err.(*elf.FormatError); !ok {
			log.Printf("다이나믹 심볼 분석 중 예상치 못한 오류 발생: %v", err)
		}
	}
	if len(symbols) == 0 {
		fmt.Println("이 파일은 심볼 정보를 포함하지 않습니다.")
		os.Exit(0) // 분석할 심볼이 없으므로 종료
	}
	// ... (심볼 목록 출력은 가독성을 위해 생략) ...

	// --- 4. syscall_filter.go를 사용해 "관심 있는" 래퍼 함수 필터링 ---
	expectSyscalls := analyzer.FilterSyscalls(symbols)
	if len(expectSyscalls) == 0 {
		fmt.Println("의존하는 시스템 콜 래퍼를 찾지 못했습니다.")
		os.Exit(0) // 분석할 래퍼가 없으므로 종료
	}
	fmt.Printf("의존하는 시스템 콜 래퍼 %d개 발견:\n", len(expectSyscalls))
	for _, sym := range expectSyscalls {
		fmt.Printf("- %s\n", sym)
	}
	fmt.Println("----------------------------------------")

	// --- 5. [신규] 핵심 로직을 Processor에 위임 ---
	fmt.Println("래퍼 함수 $\to$ 커널 시스템 콜 패턴 매핑 중...")

	// 중복 제거 (예: read@...가 여러 개 있을 수 있음)
	uniqueWrappers := make(map[string]struct{})
	for _, sym := range expectSyscalls {
		parts := strings.Split(sym, "@")
		uniqueWrappers[parts[0]] = struct{}{}
	}

	// [수정] processor.BuildSyscallMap 호출
	redisMap := processor.BuildSyscallMap(libcAnalyzer, uniqueWrappers)

	// [이동] Redis 저장 로직 (주석 처리됨)

	// --- 6. [신규] Redis에 K-V 데이터 삽입 ---
	fmt.Println("----------------------------------------")
	fmt.Println("Redis에 래퍼 $\to$ 커널 매핑 저장 중...")
	pipe := rdb.Pipeline()
	for wrapperName, kernelName := range redisMap {
		if kernelName != "" {
			pipe.Set(ctx, wrapperName, kernelName, 0)
		}
	}
	_, err = pipe.Exec(ctx)
	if err != nil {
		log.Printf("[경고] Redis 파이프라인 실행 실패: %v\n", err)
	} else {
		log.Println("  [성공] Redis에 데이터 저장 완료.")
	}

	// --- 7. 최종 JSON 출력 (Redis K-V와 동일한 맵) ---
	fmt.Println("----------------------------------------")
	fmt.Println("최종 매핑 결과 JSON (Redis K-V) 출력:")
	jsonData, err := json.MarshalIndent(redisMap, "", "  ") // redisMap을 출력
	if err != nil {
		log.Fatalf("JSON 변환 오류: %v", err)
	}
	fmt.Println(string(jsonData))
}
