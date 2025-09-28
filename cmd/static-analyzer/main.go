// cmd/static-analyzer/main.go
//# Nginx 바이너리를 분석하는 예시
//go run cmd/static-analyzer/main.go /usr/sbin/nginx

//elf파일에서 공유 라이브러리 목록과 심볼 목록을 추출하는 간단한 static analyzer 프로그램

package main

import (
	"fmt"
	"log"
	"os"
	"debug/elf"
	// 현재 프로젝트의 analyzer 패키지를 import 합니다.
	// 실제 프로젝트에서는 "your_project_module_name/pkg/analyzer"와 같은 형식이 됩니다.
	"static-analyzer/pkg/analyzer"
)

func main() {
	// 프로그램 인자 존재하는지 확인 (프로그램 이름 + 파일 경로)하고 없으면 사용법 출력
	if len(os.Args) < 2 { 
		fmt.Println("사용법: go run cmd/static-analyzer/main.go <ELF 파일 경로>")
		os.Exit(1)
	}

	// 첫 번째 인자를 파일 경로로 사용
	filePath := os.Args[1]
	fmt.Printf("🔍 분석 대상 파일: %s\n", filePath)
	fmt.Println("----------------------------------------")

	analyzer, err := analyzer.New(filePath)
    if err != nil {
        log.Fatalf("분석기 생성 오류: %v", err)
    }
    defer analyzer.Close()


	libs, err := analyzer.ExtractSharedLibs()
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
	}

	fmt.Println("----------------------------------------")

	symbols, err := analyzer.ExtractDynamicSymbols()
	if err != nil {
	    if _, ok := err.(*elf.FormatError); !ok {
    	    log.Printf("다이나믹 심볼 분석 중 예상치 못한 오류 발생: %v", err)
    	}
	}

	// 결과 출력, 심볼 목록 시원찮으면 바이너리 .text 섹션에서 직접 뽑는 방법도 고려
	if len(symbols) == 0 {
		fmt.Println("이 파일은 심볼 정보를 포함하지 않습니다.")
	} else {
		fmt.Println("바이너리가 의존하는 동적 심볼 목록:")
		for _, sym := range symbols {
			fmt.Printf("- %s\n", sym)
		}
	}

	fmt.Println("----------------------------------------")

	// 스트립 되지 않은 파일이 있다면 해당 함수사용
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

}