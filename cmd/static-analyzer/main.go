// cmd/static-analyzer/main.go
package main

import (
	"context"
	"debug/elf"
	"encoding/json"
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer" // asmanalysis 임포트
	"log"
	"os"
	"strings"

	"github.com/redis/go-redis/v9" // Redis 클라이언트 임포트
)

// !!! 중요: libc.so.6의 실제 경로는 시스템마다 다를 수 있습니다.
// (예: /lib/x86_64-linux-gnu/libc.so.6 또는 /lib64/libc.so.6)
// 동적으로 찾거나, 상수로 지정해야 합니다.
const LibcPath = "/lib/x86_64-linux-gnu/libc.so.6"

func main() {
	// 프로그램 인자 존재하는지 확인 (프로그램 이름 + 파일 경로)하고 없으면 사용법 출력
	if len(os.Args) < 2 {
		fmt.Println("사용법: go run cmd/static-analyzer/main.go <ELF 파일 경로>")
		os.Exit(1)
	}

	// [신규] Redis 클라이언트 초기화
	// 환경 변수 REDIS_ADDR에서 주소를 읽어옵니다.
	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "localhost:6379" // 환경 변수가 없으면 localhost를 기본값으로 사용
		log.Printf("[정보] REDIS_ADDR 환경 변수가 설정되지 않았습니다. 기본값(localhost:6379)으로 연결 시도...")
	}

	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr,
	})

	// Redis 연결 테스트
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
	fmt.Printf("Glibc 라이브러리 분석 중: %s\n", LibcPath)
	libcAnalyzer, err := analyzer.New(LibcPath)
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
	} else {
		fmt.Println("바이너리가 의존하는 동적 심볼 목록:")
		for _, sym := range symbols {
			fmt.Printf("- %s\n", sym)
		}
	}

	fmt.Println("----------------------------------------")

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

	// --- 5. [신규] Libc 역어셈블을 통해 커널 시스템 콜 번호 매핑 ---
	fmt.Println("래퍼 함수 $\to$ 커널 시스템 콜 패턴 매핑 중...")

	// 최종 결과 맵: map[래퍼 이름] $\to$ 커널 Syscall 이름
	redisMap := make(map[string]string) // Redis K-V 포맷용 맵

	// 중복 제거 (예: read@...가 여러 개 있을 수 있음)
	uniqueWrappers := make(map[string]struct{})
	for _, sym := range expectSyscalls { // V1의 expectSyscalls를 사용
		parts := strings.Split(sym, "@")
		uniqueWrappers[parts[0]] = struct{}{}
	}

	for wrapperName := range uniqueWrappers {
		if wrapperName == "" {
			continue
		}

		// FindKernelSyscallPatterns (복수형) 호출
		syscallPatterns, err := libcAnalyzer.FindKernelSyscallPatterns(wrapperName)

		if err != nil {
			// 1. 심볼 자체를 찾는 데 실패한 경우 (예: "fstat"이 아예 없음)
			log.Printf("  [경고] '%s' 래퍼 추적 실패: %v\n", wrapperName, err)
			continue // 다음 래퍼로
		}

		// 2. 래퍼에서 유효한 커널 시스템 콜 이름 찾기
		foundKernelName := ""
		if len(syscallPatterns) > 0 {
			fmt.Printf("  [성공] '%s' 래퍼에서 %d개의 'syscall' 패턴 발견:\n", wrapperName, len(syscallPatterns))

			for _, pattern := range syscallPatterns {
				fmt.Printf("    - 주소: 0x%x $\to$ 커널 Syscall #%d (0x%x)\n", pattern.Address, pattern.Number, pattern.Number)
				// 첫 번째로 유효한(-1이 아닌) 시스템 콜 번호를 찾으면 이름으로 변환
				if foundKernelName == "" && pattern.Number != -1 {
					if name, ok := analyzer.GetKernelSyscallName(pattern.Number); ok {
						foundKernelName = name
					}
				}
			}
		}

		// 3. 첫 번째 시도 실패 및 "64" 접미사로 재시도
		if foundKernelName == "" {
			if len(syscallPatterns) == 0 {
				log.Printf("  [정보] '%s' 래퍼에서 'syscall' 명령어를 찾지 못함 (JMP 추적 필요할 수 있음)\n", wrapperName)
			} else {
				log.Printf("  [정보] '%s' 래퍼에서 유효한 커널 시스템 콜 번호를 찾지 못함 (모두 -1 이었음)\n", wrapperName)
			}

			// "64" 접미사 재시도 로직
			if !strings.HasSuffix(wrapperName, "64") {
				newName := wrapperName + "64"
				log.Printf("  [시도] '%s'로 재시도...\n", newName)

				syscallPatterns, err = libcAnalyzer.FindKernelSyscallPatterns(newName)

				if err == nil && len(syscallPatterns) > 0 {
					fmt.Printf("  [성공] '%s' (%s) 래퍼에서 %d개의 'syscall' 패턴 발견:\n", newName, wrapperName, len(syscallPatterns))
					for _, pattern := range syscallPatterns {
						fmt.Printf("    - 주소: 0x%x $\to$ 커널 Syscall #%d (0x%x)\n", pattern.Address, pattern.Number, pattern.Number)
						if foundKernelName == "" && pattern.Number != -1 {
							if name, ok := analyzer.GetKernelSyscallName(pattern.Number); ok {
								foundKernelName = name
							}
						}
					}
				} else {
					log.Printf("  [실패] '%s' 재시도 실패 (오류: %v, 패턴: %d개)\n", newName, err, len(syscallPatterns))
				}
			}
		}

		// 4. [수정] 최종 맵에 저장 (Tracepoint 필터링 포함)
		if foundKernelName != "" {
			// [신규] 커널 시스템 콜 이름으로 Tracepoint 존재 여부 확인
			if analyzer.IsTracepointAvailable(foundKernelName) {
				redisMap[wrapperName] = foundKernelName
				log.Printf("  [매핑] %s $\to$ %s (Tracepoint: ✓)\n", wrapperName, foundKernelName)
			} else {
				log.Printf("  [정보] %s $\to$ %s (Tracepoint: ✗ - 필터링됨)\n", wrapperName, foundKernelName)
			}
		}
	}

	// --- 6. [신규] Redis에 K-V 데이터 삽입 ---
	fmt.Println("----------------------------------------")
	fmt.Println("Redis에 래퍼 $\to$ 커널 매핑 저장 중...")

	// 파이프라인 생성 (여러 SET 명령을 효율적으로 전송)
	pipe := rdb.Pipeline()

	// redisMap (map[string]string)을 순회하며 파이프라인에 추가
	for wrapperName, kernelName := range redisMap {
		if kernelName != "" { // 유효한 매핑만 저장
			pipe.Set(ctx, wrapperName, kernelName, 0) // (key, value, expiration)
		}
	}

	// 파이프라인 실행
	_, err = pipe.Exec(ctx)
	if err != nil {
		log.Printf("[경고] Redis 파이프라인 실행 실패: %v\n", err)
	} else {
		log.Println("  [성공] Redis에 데이터 저장 완료.")
	}

	// --- 7. 최종 JSON 출력 (Redis K-V와 동일한 맵) ---
	fmt.Println("----------------------------------------")
	fmt.Println("최종 매핑 결과 JSON (Redis K-V) 출력:")
	// json.MarshalIndent를 사용하여 사람이 보기 좋게 포맷팅된 JSON 생성
	jsonData, err := json.MarshalIndent(redisMap, "", "  ") // redisMap을 출력
	if err != nil {
		log.Fatalf("JSON 변환 오류: %v", err)
	}

	// []byte 타입의 jsonData를 string으로 변환하여 출력
	fmt.Println(string(jsonData))
}
