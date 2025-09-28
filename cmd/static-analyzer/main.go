// cmd/static-analyzer/main.go
//# Nginx 바이너리를 분석하는 예시
//go run cmd/static-analyzer/main.go /usr/sbin/nginx
package main

import (
	"fmt"
	"log"
	"os"
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


	// 공유 라이브러리 목록 추출 함수 호출
	libs, err := analyzer.ExtractSharedLibs(filePath)
	if err != nil {
		log.Fatalf("오류 발생: %v", err)
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

	symbols, err := analyzer.ExtractSymbols(filePath)
	if err != nil {
		log.Fatalf("오류 발생: %v", err)
	}

	// 결과 출력, 심볼 목록 시원찮으면 바이너리 .text 섹션에서 직접 뽑는 방법도 고려
	if len(symbols) == 0 {
		fmt.Println("이 파일은 심볼 정보를 포함하지 않습니다.")
	} else {
		fmt.Println("발견된 공유 라이브러리의 심볼 목록:")
		for _, sym := range symbols {
			fmt.Printf("- %s\n", sym)
		}
	}

}