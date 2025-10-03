// pkg/analyzer/elf_parser.go
package analyzer

import (
	"debug/elf"
	"fmt"

	//"io"
	"github.com/knightsc/gapstone" //디스어셈블 라이브러리
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

func (a *ELFAnalyzer) FindSyscallSymbolIndex() (uint32, error) {
	// 1. 동적 심볼들을 읽습니다.
	dynamicSymbols, err := a.elfFile.DynamicSymbols()
	if err != nil {
		return 0, fmt.Errorf("동적 심볼을 읽을 수 없습니다: %w", err)
	}

	// 2. "syscall"와 이름이 일치하는 심볼을 찾고, 해당 심볼의 인덱스를 반환
	for i, sym := range dynamicSymbols {
		if sym.Name == "syscall" {
			fmt.Println("디버깅출력 syscall 심볼 인덱스 찾음, 인덱스:", i+1)
			return uint32(i + 1), nil
		}
	}
	return 0, fmt.Errorf("'syscall@Base' 심볼을 찾을 수 없습니다")
}

// Section: 내부 elf.File의 Section 메서드를 호출, name에 해당하는 섹션 반환
func (a *ELFAnalyzer) Section(name string) *elf.Section {
	return a.elfFile.Section(name)
}

// ExtractAsmCode : .text 섹션의 어셈블리 코드와 시작 주소 추출
func (a *ELFAnalyzer) ExtractAsmCode() ([]gapstone.Instruction, uint64, error) {
	textSect := a.Section(".text")
	if textSect == nil {
		return nil, 0, fmt.Errorf(".text 섹션을 찾을 수 없습니다. (섹션이 스트립되었을 수 있습니다)")
	}

	startAddr := textSect.Addr   // 섹션의 가상 주소(Virtual Address) 추출
	data, err := textSect.Data() // 섹션의 실제 데이터 추출
	if err != nil {
		return nil, 0, fmt.Errorf(".text 섹션 데이터 읽기 실패: %v", err)
	}

	//gapstone 버전설정
	engine, err := gapstone.New(
		gapstone.CS_ARCH_X86,
		gapstone.CS_MODE_64,
	)
	fmt.Println("ARCH_X86_64 , MODE_64")

	// 디테일 옵션 활성화
	err = engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON)
	if err != nil {
		return nil, 0, fmt.Errorf("Capstone 옵션 설정 실패: %w", err)
	}

	if err != nil {
		return nil, 0, fmt.Errorf("Capstone 엔진 생성 실패: %w", err)
	}
	defer engine.Close()

	maj, min := engine.Version()
	fmt.Printf("Capstone 버전: %d.%d\n", maj, min)

	insns, err := engine.Disasm(data, startAddr, 0) //gapstone를 이용한 디스어셈블

	if err != nil {
		// Disasm 실패 시 오류 반환
		return nil, 0, fmt.Errorf("Disasm 실패: %w", err)
	}
	return insns, startAddr, nil
}
