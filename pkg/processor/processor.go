package processor

import (
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer"
	"ips_bpf/static-analyzer/pkg/syscalls" // [신규] syscalls 패키지 임포트
	"log"
	"strings"
)

// BuildSyscallMap은 Libc 분석기와 래퍼 목록을 받아
// 최종적인 {wrapper: kernelSyscall} 맵을 생성합니다.
func BuildSyscallMap(libcAnalyzer *analyzer.ELFAnalyzer, uniqueWrappers map[string]struct{}) map[string]string {

	// [이동] main.go에서 이동
	redisMap := make(map[string]string) // Redis K-V 포맷용 맵

	// [이동] main.go의 for 루프 전체
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
					// [수정] analyzer. -> syscalls.
					if name, ok := syscalls.GetKernelSyscallName(pattern.Number); ok {
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
							// [수정] analyzer. -> syscalls.
							if name, ok := syscalls.GetKernelSyscallName(pattern.Number); ok {
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
			// [수정] analyzer. -> syscalls.
			if syscalls.IsTracepointAvailable(foundKernelName) {
				redisMap[wrapperName] = foundKernelName
				log.Printf("  [매핑] %s $\to$ %s (Tracepoint: ✓)\n", wrapperName, foundKernelName)
			} else {
				log.Printf("  [정보] %s $\to$ %s (Tracepoint: ✗ - 필터링됨)\n", wrapperName, foundKernelName)
			}
		}
	}

	return redisMap
}
