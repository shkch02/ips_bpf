// pkg/analyzer/elf_parser.go
package analyzer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"ips_bpf/static-analyzer/pkg/asmanalysis"

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

// Close :  ELF 파일을 닫음. defer와 함께 사용.
func (a *ELFAnalyzer) Close() {
	a.elfFile.Close()
}

// ExtractSharedLibs :  의존하는 공유 라이브러리 목록을 추출, 단순 라이브러리 목록 추출은 정확한 시스템콜 추출할 수 없기에 폐기
func (a *ELFAnalyzer) ExtractSharedLibs() ([]string, error) {
	return a.elfFile.ImportedLibraries()
}

// ExtractDynamicSymbols : 해당 elf가 참조하는 동적 심볼 추출하여 문자열string으로 반환
func (a *ELFAnalyzer) ExtractDynamicSymbols() ([]string, error) {
	dynamicSymbols, err := a.elfFile.DynamicSymbols() //elf.File의 DynamicSymbols 메서드 호출
	if err != nil {
		return nil, fmt.Errorf("동적 심볼 추출 실패: %w", err)
	}

	symbolNames := make([]string, 0, len(dynamicSymbols)) //make(type, 초기 길이, 용량) 슬라이드 생성함수
	for _, sym := range dynamicSymbols {
		symbolNames = append(symbolNames, sym.Name) //append(대상 슬라이스, 추가할 값)슬라이스 추가 함수
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

// GOT : 심볼된 주소를 가상주소로 매핑하는 테이블
// FinndSysccallSymbolAddr : syscall 함수를 가리키는 포인터가 저장된 주소(GOT 엔트리 주소) 반환
func (a *ELFAnalyzer) FindSyscallSymbolAddr() (uint64, error) {
	// 동적 심볼 목록 추출
	symbolNames, err := a.ExtractDynamicSymbols()

	var syscallsymbolindex uint32
	// "syscall"와 이름이 일치하는 심볼을 찾고, 해당 심볼의 인덱스를 반환
	for i, sym := range symbolNames {
		if sym == "syscall" {
			// elf.File.DynamicSymbols()는 Index 1부터 시작하는 배열을 반환
			// 실제 심볼 인덱스는 i+1 (Index 0은 UNDEF)
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

	var relocs []elf.Rela64
	const relaSize = 24 // 64비트 Rela 엔트리 크기 (Off: 8, Info: 8, Addend: 8 바이트)

	// 데이터 크기가 Rela 엔트리 크기의 배수인지 확인
	if len(data)%relaSize != 0 {
		return 0, fmt.Errorf("재배치 섹션 크기가 Rela 엔트리 크기의 배수가 아닙니다")
	}

	// ELF 파일의 바이트 순서를 사용
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

	for _, rel := range relocs {
		relType := elf.R_X86_64(rel.Info & 0xFFFFFFFF)
		relSymIndex := uint32(rel.Info >> 32)

		// 타입이 R_X86_64_GLOB_DAT 이고, 심볼 인덱스가 syscall@Base의 인덱스와 일치하는지 확인
		if relType == elf.R_X86_64_GLOB_DAT && relSymIndex == syscallsymbolindex {
			// rel.Off 필드가 GOT 엔트리의 주소
			return rel.Off, nil // 0x11a3c8 반환
		}
	}

	return 0, fmt.Errorf("'syscall' 심볼주소을 찾을 수 없습니다")
}

// Section: 내부 elf.File의 Section 메서드를 호출, name에 해당하는 섹션 반환
func (a *ELFAnalyzer) Section(name string) *elf.Section {
	return a.elfFile.Section(name)
}

// ExtractAsmCode : .text 섹션의 기계어를 어셈블리 코드로 바꾸고 시작 주소 추출
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

// FindKernelSyscallPatterns는 libc.so.6와 같은 라이브러리 파일 내에서
// 특정 심볼 이름(예: "open")을 인자로 받아, 해당 함수가 호출하는
// 모든 커널 시스템 콜 패턴을 반환합니다.
func (a *ELFAnalyzer) FindKernelSyscallPatterns(symbolName string) ([]asmanalysis.SyscallInfo, error) {
	// 1. libc.so.6의 동적 심볼 테이블에서 symbolName을 찾습니다.
	symbols, err := a.elfFile.DynamicSymbols()
	if err != nil {
		return nil, fmt.Errorf("동적 심볼 읽기 실패: %w", err)
	}

	// libsoc.6 내에서 symbolName과 일치하는 심볼을 찾음
	var targetSymbol *elf.Symbol
	for i, sym := range symbols {
		if sym.Name == symbolName {
			targetSymbol = &symbols[i]
			break
		}
	}
	if targetSymbol == nil {
		// [난관 1: 심볼 매핑]
		// "open" 심볼이 없고 "__open"만 있을 수 있습니다.
		// 여기에 "open" -> "__open"으로 다시 검색하는 예외 처리 로직을 추가할 수 있습니다.
		// (예: if strings.HasPrefix(symbolName, "__") ... else ... FindKernelSyscallPatterns("__" + symbolName))
		return nil, fmt.Errorf("'%s' 심볼을 찾을 수 없음", symbolName)
	}

	// 2. 심볼의 주소(Value)와 크기(Size)를 이용해 .text 섹션에서 코드 추출
	textSect := a.Section(".text")
	// ... (오프셋 및 크기 계산 로직은 V1 계획서와 동일) ...
	// (offset, size, data, code 추출...)
	offset := targetSymbol.Value - textSect.Addr
	size := targetSymbol.Size
	if size == 0 {
		size = 4096 // 기본 크기
	}
	data, err := textSect.Data()
	if err != nil {
		return nil, fmt.Errorf(".text 데이터 읽기 실패: %w", err)
	}
	if offset >= uint64(len(data)) {
		return nil, fmt.Errorf("심볼 주소가 .text 범위를 벗어남")
	}
	end := offset + size
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	code := data[offset:end]

	// 3. Gapstone(Capstone)으로 추출된 코드 역어셈블
	engine, err := gapstone.New(gapstone.CS_ARCH_X86, gapstone.CS_MODE_64)
	if err != nil {
		return nil, fmt.Errorf("Capstone 엔진 생성 실패: %w", err)
	}
	defer engine.Close()
	engine.SetOption(gapstone.CS_OPT_DETAIL, gapstone.CS_OPT_ON) // JMP 추적 등에 필요

	insns, err := engine.Disasm(code, targetSymbol.Value, 0)
	if err != nil {
		return nil, fmt.Errorf("Disasm 실패: %w", err)
	}

	// [난관 1: JMP 추적 심화]
	// V1 계획서의 JMP 추적을 여기에 구현할 수 있습니다.
	// if insns[0].Mnemonic == "jmp" && insns[0].X86.Operands[0].Type == gapstone.X86_OP_IMM {
	//    jmpTargetAddr := insns[0].X86.Operands[0].Imm
	//    // jmpTargetAddr를 기준으로 다시 Disasm... (복잡도 증가)
	// }

	// 4. [신규] 어셈블리 트레이서 호출
	// asmanalysis 패키지의 재작성된 함수를 호출합니다.
	return asmanalysis.FindAllSyscalls(insns)
}
