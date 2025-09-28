// pkg/analyzer/elf_parser.go
package analyzer

import (
	"debug/elf"
	"fmt"
)

// ELFAnalyzer는 파싱된 ELF 파일 정보를 담는 구조체
type ELFAnalyzer struct {
    elfFile *elf.File
}

// New는 파일 경로를 받아 새로운 ELFAnalyzer를 생성합니다.
func New(filePath string) (*ELFAnalyzer, error) {
    elfFile, err := elf.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("ELF 파일을 여는 데 실패했습니다: %w", err)
    }
    return &ELFAnalyzer{elfFile: elfFile}, nil
}

// Close는 ELF 파일을 닫습니다. defer와 함께 사용해야 합니다.
func (a *ELFAnalyzer) Close() {
    a.elfFile.Close()
}


// ExtractSharedLibs는 지정된 ELF 파일 경로를 받아 해당 파일이 의존하는
// 공유 라이브러리(.so) 목록을 추출합니다.
func (a *ELFAnalyzer) ExtractSharedLibs() ([]string, error) {
    return a.elfFile.ImportedLibraries()
    // 에러 처리는 main 쪽에서 더 간단하게 할 수 있습니다.
}

// ExtractSymbols는 지정된 ELF 파일 경로를 받아 해당 파일에 포함된 심볼 목록을 추출합니다. (스트립 되지 않은 시스템콜을 뽑음)
// 심볼 :  함수 이름, 변수 이름 등
func (a *ELFAnalyzer) ExtractDynamicSymbols() ([]string, error) {
    dynamicSymbols, err := a.elfFile.DynamicSymbols()
    if err != nil {
        return nil, fmt.Errorf("동적 심볼 추출 실패: %w", err)
    }

    symbolNames := make([]string, 0, len(dynamicSymbols))
    for _, sym := range dynamicSymbols {
        symbolNames = append(symbolNames, sym.Name)
    }
    return symbolNames, nil
}

//스트립 되지 않은 elf있다면 해당 함수 사용
func (a *ELFAnalyzer) ExtractSymbols() ([]string, error) {
    Symbols, err := a.elfFile.Symbols()
    if err != nil {
        return nil, fmt.Errorf("심볼 추출 실패: %w", err)
    }

    symbolNames := make([]string, 0, len(Symbols))
    for _, sym := range Symbols {
        symbolNames = append(symbolNames, sym.Name)
    }
    return symbolNames, nil
}
