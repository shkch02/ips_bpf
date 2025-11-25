// cmd/static-analyzer/main.go
// 커밋위한 주석
package main

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer"
	"ips_bpf/static-analyzer/pkg/config"    // [신규]
	"ips_bpf/static-analyzer/pkg/processor" // [신규]
	"ips_bpf/static-analyzer/pkg/storage"
	"log"
	"os"
	"strings"
)

func main() {
	// 프로그램 인자 존재하는지 확인 (프로그램 이름 + 파일 경로)하고 없으면 사용법 출력
	if len(os.Args) < 2 {
		fmt.Println("사용법: go run cmd/static-analyzer/main.go <ELF 파일 경로>")
		os.Exit(1)
	}

	//레디스 호출
	ctx := context.Background()
	redisAddr := config.LoadRedisAddr()
	redisPassword := config.LoadRedisPassword() // config.go에서 "CCSL_REDIS_PASSWORD"를 읽습니다.
	rdb, err := storage.NewRedisClient(redisAddr, redisPassword)
	if err != nil {
		log.Fatalf("Redis 클라이언트 생성 오류: %v", err)
	}
	defer rdb.Close()
	fmt.Printf("Redis 클라이언트 생성 완료: %s\n", redisAddr)

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

	// 역어셈 및 분석을 통해 매핑 생성
	redisMap := processor.BuildSyscallMap(libcAnalyzer, uniqueWrappers)

	// [이동] Redis 저장 로직 (주석 처리됨)

	// --- 6. [신규] Redis에 K-V 데이터 삽입 ---
	fmt.Println("----------------------------------------")
	fmt.Println("Redis에 래퍼 $\to$ 커널 매핑 및 Set 저장 중...")
	pipe := rdb.Pipeline()

	// Set에 추가할 시스템 콜 목록을 별도로 수집
	var callableSyscalls []interface{}

	for wrapperName, kernelName := range redisMap {
		if kernelName != "" {
			// 1. 기존의 개별 K-V 데이터 저장 (Keep this for debugging/lookup)
			pipe.Set(ctx, wrapperName, kernelName, 0)

			// 2. [추가] Set에 커널 시스템 콜 이름만 추가 (웹 서비스에서 사용)
			callableSyscalls = append(callableSyscalls, kernelName)
		}
	}

	// [추가] Set에 모든 시스템 콜 이름을 한 번에 저장 (Set Key는 SyscallService에 정의된 값)
	if len(callableSyscalls) > 0 {
		pipe.SAdd(ctx, "cluster_callable_syscalls", callableSyscalls...) // SAdd 사용
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
