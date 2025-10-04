// pkg/analyzer/elf_parser.go
package analyzer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
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
		fmt.Println("디버깅 출력 dynamicSymbols :",dynamicSymbols)
		symbolNames = append(symbolNames, sym.Name)
		fmt.Println("symbolNames :",symbolNames)
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

func (a *ELFAnalyzer) FindSyscallSymbolAddr() (uint64, error) {
	symbolNames, err := a.ExtractDynamicSymbols()

	var syscallsymbolindex uint32
	// 2. "syscall"와 이름이 일치하는 심볼을 찾고, 해당 심볼의 인덱스를 반환
	for i, sym := range symbolNames {
		if sym == "syscall" {
			// elf.File.DynamicSymbols()는 Index 1부터 시작하는 배열을 반환합니다.
			// 실제 심볼 인덱스는 i+1 입니다. (Index 0은 UNDEF)
			syscallsymbolindex = uint32(i + 1)
		}
	}

	// 재배치 엔트리를 읽음
	relaDyn := a.Section(".rela.dyn")
	if relaDyn == nil {
		return 0, fmt.Errorf(".rela.dyn 섹션을 찾을 수 없습니다")
	}

	data, err := relaDyn.Data()
	if err != nil {
		// 오류 처리
	}

	// ⭐⭐ 4. 원시 데이터를 []elf.Rela64 목록으로 수동 파싱 ⭐⭐
	var relocs []elf.Rela64
	const relaSize = 24 // 64비트 Rela 엔트리 크기 (Off: 8, Info: 8, Addend: 8 바이트)

	// 데이터 크기가 Rela 엔트리 크기의 배수인지 확인
	if len(data)%relaSize != 0 {
		return 0, fmt.Errorf("재배치 섹션 크기가 Rela 엔트리 크기의 배수가 아닙니다")
	}

	// ELF 파일의 바이트 순서를 사용합니다.
	byteOrder := a.elfFile.ByteOrder

	for i := 0; i < len(data); i += relaSize {
		var rela64 elf.Rela64

		// 바이트 슬라이스를 Rela64 구조체로 파싱
		err := binary.Read(bytes.NewReader(data[i:i+relaSize]), byteOrder, &rela64)
		if err != nil {
			return 0, fmt.Errorf("Rela64 엔트리 파싱 오류: %w", err)
		}
		relocs = append(relocs, rela64)
	}
	// 3. 재배치 엔트리를 순회하며 조건에 맞는 것을 찾습니다.
	for _, rel := range relocs {
		// R_X86_64_GLOB_DAT (Type 6)은 GOT 엔트리를 채우기 위한 재배치 타입입니다.
		// rel.Info의 하위 32비트가 타입, 상위 32비트가 심볼 인덱스입니다.
		relType := elf.R_X86_64(rel.Info & 0xFFFFFFFF)
		relSymIndex := uint32(rel.Info >> 32)

		// 타입이 R_X86_64_GLOB_DAT 이고, 심볼 인덱스가 syscall@Base의 인덱스와 일치하는지 확인합니다.
		if relType == elf.R_X86_64_GLOB_DAT && relSymIndex == syscallsymbolindex {
			// rel.Off 필드가 바로 objdump에서 본 GOT 엔트리의 주소입니다.
			return rel.Off, nil // 0x11a3c8 반환
		}
	}

	return 0, fmt.Errorf("'syscall' 심볼주소을 찾을 수 없습니다")
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
