// cmd/static-analyzer/main.go
//# Nginx 바이너리를 분석하는 예시
//go run cmd/static-analyzer/main.go /usr/sbin/nginx
//elf파일에서 공유 라이브러리 목록과 심볼 목록을 추출하는 간단한 static analyzer 프로그램

package main

import (
	"debug/elf"
	"encoding/json"
	"fmt"
	"ips_bpf/static-analyzer/pkg/analyzer"

	//"ips_bpf/static-analyzer/pkg/asmanalysis"
	"log"
	"os"
)

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

	analyzer, err := analyzer.New(filePath)
	if err != nil {
		log.Fatalf("분석기 생성 오류: %v", err)
	}
	defer analyzer.Close()

	//단순 라이브러리 목록 추출은 정확한 시스템콜 추출할 수 없기에 폐기, 활용성을 위해 코드에는 남기겠음
	/*libs, err := analyzer.ExtractSharedLibs()
	if err != nil {
		// FormatError는 라이브러리가 없는 정상 케이스로 간주하고, 그 외의 에러만 로그 출력
		if _, ok := err.(*elf.FormatError); !ok {
			log.Printf("공유 라이브러리 분석 중 예상치 못한 오류 발생: %v", err)
		}
	}

	// 결과 출력
	if len(libs) == 0 {
		fmt.Println("이 파일은 동적 공유 라이브러리에 의존하지 않습니다.")
	} else {
		fmt.Println("발견된 공유 라이브러리 목록:")
		for _, lib := range libs {
			fmt.Printf("- %s\n", lib)
		}
	}*/

	fmt.Println("----------------------------------------")

	symbols, err := analyzer.ExtractDynamicSymbols() //이거 필터링하면됨
	if err != nil {
		if _, ok := err.(*elf.FormatError); !ok {
			log.Printf("다이나믹 심볼 분석 중 예상치 못한 오류 발생: %v", err)
		}
	}

	if len(symbols) == 0 {
		fmt.Println("이 파일은 심볼 정보를 포함하지 않습니다.")
	} else {
		fmt.Println("바이너리가 의존하는 동적 심볼 목록:")
		for _, sym := range symbols {
			fmt.Printf("- %s\n", sym)
		}
	}

	fmt.Println("----------------------------------------")

	//받은 심볼 슬라이스와 시스템콜 비교해서 시스템콜인 목록만 남기기,  안에서 set해시 활용
	expectSyscalls := analyzer.FilterSyscalls(symbols)

	if len(expectSyscalls) > 0 {
		fmt.Println("추출된 시스템 콜 목록:")
		for _, sym := range expectSyscalls {
			fmt.Printf("- %s\n", sym)
		}
	} else {
		fmt.Println("의존하는 시스템 콜을 찾지 못했습니다.")
	}

	//json으로 변환
	fmt.Println("JSON 출력:")
	// json.MarshalIndent를 사용하여 사람이 보기 좋게 포맷팅된 JSON 생성
	jsonData, err := json.MarshalIndent(expectSyscalls, "", "  ")
	if err != nil {
		log.Fatalf("JSON 변환 오류: %v", err)
	}

	// []byte 타입의 jsonData를 string으로 변환하여 출력
	fmt.Println(string(jsonData))

	// 스트립 되지 않은 파일이 있다면 해당 함수사용, flag로 옵션으로 끄고 켤수도있음 필요하면 구현
	/*symbols, err := analyzer.ExtractSymbols()
		if err != nil {
		    if _, ok := err.(*elf.FormatError); !ok {
	    	    log.Printf("다이나믹 심볼 분석 중 예상치 못한 오류 발생: %v", err)
	    	}
		}


		if len(symbols) == 0 {
			fmt.Println("이 파일은 심볼 정보를 포함하지 않습니다.")
		} else {
			fmt.Println("바이너리가 의존하는 동적 심볼 목록:")
			for _, sym := range symbols {
				fmt.Printf("- %s\n", sym)
			}
		}*/

	/*insns, startAddr, err := analyzer.ExtractAsmCode()
	if err != nil {
		log.Printf("다이나믹 심볼 분석 중 예상치 못한 오류 발생: %v", err)
	}
	fmt.Printf("시작주소 : 0x%x\n", startAddr)
	for _, asm := range insns {
		fmt.Printf("0x%x:\t%s\t%s\n", asm.Address, asm.Mnemonic, asm.OpStr)
	}*/

	/*()
	SyscallAddr, err := analyzer.FindSyscallSymbolAddr()
	if err != nil {
		log.Printf("syscall 심볼 주소 찾기 중 오류 발생: %v", err)
	}

	syscalls, err := asmanalysis.FindSyscalls(SyscallAddr, insns)
	if err != nil {
		log.Printf("systemcall 추출중 오류 발생: %v", err)
	}

	fmt.Println("발견된 시스템 콜 목록:")
	for _, sc := range syscalls {
		fmt.Printf("- 주소: 0x%x, 시스템 콜 번호: %d\n", sc.Address, sc.Number)
	}*/
}
