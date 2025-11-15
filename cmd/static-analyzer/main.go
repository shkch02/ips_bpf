// go run ./cmd/static-analyzer/main.go ../syscalltest2
// go run cmd/static-analyzer/main.go /usr/sbin/nginx
// cmd/static-analyzer/main.go
package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer"
	"ips_bpf/static-analyzer/pkg/asmanalysis" // asmanalysis 임포트
	"log"
	"os"
	"strings"
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
	// (이 단계는 man 페이지 파싱을 그대로 활용하여 어떤 심볼을 추적할지 결정합니다)
	expectSyscalls := analyzer.FilterSyscalls(symbols) // V1의 JSON 출력 대상

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

	// 최종 결과 맵: map[래퍼 이름] $\to$ []SyscallInfo
	kernelSyscallMap := make(map[string][]asmanalysis.SyscallInfo)

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
			kernelSyscallMap[wrapperName] = nil // nil 또는 빈 슬라이스
			continue                            // 다음 래퍼로
		}

		if len(syscallPatterns) > 0 {
			// 2. 첫 번째 시도(예: "fstat")에서 'syscall'을 바로 찾은 경우 (성공)
			fmt.Printf("  [성공] '%s' 래퍼에서 %d개의 'syscall' 패턴 발견:\n", wrapperName, len(syscallPatterns))
			for _, pattern := range syscallPatterns {
				fmt.Printf("    - 주소: 0x%x $\to$ 커널 Syscall #%d (0x%x)\n", pattern.Address, pattern.Number, pattern.Number)
			}
			kernelSyscallMap[wrapperName] = syscallPatterns
			continue // 다음 래퍼로
		}

		// 3. 첫 번째 시도가 실패한 경우 (len == 0, JMP 추적 필요)
		log.Printf("  [정보] '%s' 래퍼에서 'syscall' 명령어를 찾지 못함 (JMP 추적 필요할 수 있음)\n", wrapperName)

		// 4. [신규] "64" 접미사로 재시도
		//    (단, wrapperName이 이미 "64"로 끝나지 않는 경우에만)
		if !strings.HasSuffix(wrapperName, "64") {
			newName := "__" + wrapperName + "64"
			log.Printf("  [시도] '%s'로 재시도...\n", newName)

			// "fstat64"와 같은 새 이름으로 다시 함수 호출
			syscallPatterns, err = libcAnalyzer.FindKernelSyscallPatterns(newName)

			if err == nil && len(syscallPatterns) > 0 {
				// 5. 재시도 성공
				fmt.Printf("  [성공] '%s' (%s) 래퍼에서 %d개의 'syscall' 패턴 발견:\n", newName, wrapperName, len(syscallPatterns))
				for _, pattern := range syscallPatterns {
					fmt.Printf("    - 주소: 0x%x $\to$ 커널 Syscall #%d (0x%x)\n", pattern.Address, pattern.Number, pattern.Number)
				}
				// 결과는 "fstat" (원본 래퍼 이름) 키에 저장합니다.
				kernelSyscallMap[wrapperName] = syscallPatterns
				continue // 다음 래퍼로
			} else {
				// 6. 재시도 실패
				log.Printf("  [실패] '%s' 재시도 실패 (오류: %v, 패턴: %d개)\n", newName, err, len(syscallPatterns))
			}
		}

		// 7. 최종 실패 (재시도를 안 했거나, 재시도도 실패한 경우)
		kernelSyscallMap[wrapperName] = []asmanalysis.SyscallInfo{}
	}

	// --- 6. 최종 JSON 출력 ---
	fmt.Println("----------------------------------------")
	fmt.Println("최종 매핑 결과 JSON 출력:")
	// json.MarshalIndent를 사용하여 사람이 보기 좋게 포맷팅된 JSON 생성
	jsonData, err := json.MarshalIndent(kernelSyscallMap, "", "  ") // V2의 kernelSyscallMap을 출력
	if err != nil {
		log.Fatalf("JSON 변환 오류: %v", err)
	}

	// []byte 타입의 jsonData를 string으로 변환하여 출력
	fmt.Println(string(jsonData))
}
