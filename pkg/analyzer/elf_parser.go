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

// New : ELFAnalyzer 구조체 생성
func New(filePath string) (*ELFAnalyzer, error) {
    elfFile, err := elf.Open(filePath)
    if err != nil {
        return nil, fmt.Errorf("ELF 파일을 여는 데 실패했습니다: %w", err)
    }
    return &ELFAnalyzer{elfFile: elfFile}, nil
}

// Close :  ELF 파일을 닫습니다. defer와 함께 사용해야 합니다.
func (a *ELFAnalyzer) Close() {
    a.elfFile.Close()
}


// ExtractSharedLibs :  의존하는 공유 라이브러리 목록을 추출
func (a *ELFAnalyzer) ExtractSharedLibs() ([]string, error) {
    return a.elfFile.ImportedLibraries()
}

// ExtractDynamicSymbols : 동적 심볼 추출
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

// ExtractSymbols : 스트립 되지 않은 elf대상으로 모든 심볼 추출
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
