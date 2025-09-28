// pkg/analyzer/elf_parser.go
package analyzer

import (
	"debug/elf"
	"fmt"
)

// ExtractSharedLibs는 지정된 ELF 파일 경로를 받아 해당 파일이 의존하는
// 공유 라이브러리(.so) 목록을 추출합니다.
func ExtractSharedLibs(filePath string) ([]string, error) {
	// ELF 파일 열기
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("ELF 파일을 여는 데 실패했습니다: %w", err)
	}
	defer elfFile.Close()

	// 동적 섹션에서 공유 라이브러리 목록 가져오기
	sharedLibs, err := elfFile.ImportedLibraries() //debug/elf 패키지의 ImportedLibraries 메서드 사용, 
	if err != nil {
		// 동적 섹션이 없는 경우, 빈 목록과 nil 에러를 반환할 수 있습니다.
		if _, ok := err.(*elf.FormatError); ok {
			return []string{}, nil // 동적으로 링크되지 않은 실행 파일일 수 있습니다.
		}
		return nil, fmt.Errorf("공유 라이브러리를 가져오는 데 실패했습니다: %w", err)
	}

	return sharedLibs, nil
}

// ExtractSymbols는 지정된 ELF 파일 경로를 받아 해당 파일에 포함된 심볼 목록을 추출합니다. (스트립 되지 않은 시스템콜을 뽑음)
// 심볼 :  함수 이름, 변수 이름 등
func ExtractSymbols(filePath string) ([]string, error) {
	// ELF 파일 열기
	elfFile, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("ELF 파일을 여는 데 실패했습니다: %w", err)
	}
	defer elfFile.Close()

	// 심볼 테이블에서 심볼 목록 가져오기
	symbols, err := elfFile.Symbols() //symbols 추출
	if err != nil {
		// 심볼 테이블이 없는 경우, 빈 목록과 nil 에러를 반환할 수 있습니다.
		if _, ok := err.(*elf.FormatError); ok {
			return []string{}, nil // 심볼 정보가 없는 실행 파일일 수 있습니다.(스트립된 경우 심볼정보 추출 불가 )
		}
		return nil, fmt.Errorf("심볼을 가져오는 데 실패했습니다: %w 스트립된 파일일 가능성 농후", err)
	}