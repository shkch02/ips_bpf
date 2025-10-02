package asmanalysis

import (
	"fmt"

	"github.com/knightsc/gapstone"
)

//왜 커밋안되냐고
//
//
//

// SyscallInfo는 발견된 시스템 콜의 정보를 담는 구조체입니다.
type SyscallInfo struct {
	Address uint64 // syscall 명령어의 주소
	Number  int64  // 호출 시점의 rax 값 (시스템 콜 번호)
}

// FindSyscalls는 디스어셈블된 명령어 목록을 분석하여 시스템 콜 호출을 찾습니다.
func FindSyscalls(instructions []gapstone.Instruction) ([]SyscallInfo, error) {
	var results []SyscallInfo
	fmt.Println("FindSyscalls 디버깅용 출력")
	// rax 레지스터의 마지막 값을 추적하기 위한 변수.
	// -1은 아직 rax 값이 설정된 적 없음을 의미하는 초기값.
	lastRaxValue := int64(-1)

	for _, insn := range instructions {
		// X86 관련 정보가 없는 명령어 방어코드
		if insn.X86 == nil {
			fmt.Println("디버깅용 출력:,insn.X86 == nil, continue")
			continue
		}

		if insn.OpStr == "" {
			continue
		}

		//fmt.Println("디버깅용 출력 forloop 내부임 ---------------------") //디버깅용 출력
		fmt.Printf("디버깅용 출력:insn.Address%x", insn.Address)
		//fmt.Println("디버깅용 출력:insn.Mnemonic", insn.Mnemonic)
		fmt.Printf("디버깅용 출력:insn.OpStr의 실제 값: s : [%s] , +v : [%+v] ,v : [%v] \n", insn.OpStr, insn.OpStr, insn.OpStr)

		// 1-1. 'mov rax, 0xN' 또는 'mov eax, 0xN' 패턴 찾기
		if insn.Mnemonic == "mov" && len(insn.X86.Operands) == 2 {
			// insn.X86.Operands는 슬라이스이므로, 인덱스로 각 피연산자에 접근합니다.
			//fmt.Println(insn.X86.Operands[0].Type) 접근 가이드
			op0 := insn.X86.Operands[0] // 첫 번째 피연산자 (destination)
			op1 := insn.X86.Operands[1] // 두 번째 피연산자 (source)

			// 첫 번째 피연산자가 레지스터이고, rax 또는 eax인지 확인합니다.
			if op0.Type == gapstone.X86_OP_REG && (op0.Reg == gapstone.X86_REG_RAX || op0.Reg == gapstone.X86_REG_EAX) {
				// 두 번째 피연산자가 즉시값인지 확인합니다.
				if op1.Type == gapstone.X86_OP_IMM {
					// op1의 Imm 필드에서 값을 가져옵니다.
					lastRaxValue = op1.Imm
				}
			}
		}

		// 1-2. 'xor eax, eax' 패턴 찾기
		if insn.Mnemonic == "xor" && len(insn.X86.Operands) == 2 {
			// 여기도 마찬가지로 인덱스를 사용합니다.
			op0 := insn.X86.Operands[0]
			op1 := insn.X86.Operands[1]

			// 'xor eax, eax'는 두 피연산자가 모두 eax인 경우입니다.
			if op0.Type == gapstone.X86_OP_REG && op0.Reg == gapstone.X86_REG_EAX &&
				op1.Type == gapstone.X86_OP_REG && op1.Reg == gapstone.X86_REG_EAX {
				lastRaxValue = 0
			}
		}

		// --- 2. syscall 명령어 탐지 ---
		if insn.Mnemonic == "syscall" {
			// syscall을 찾았을 때, 이전에 rax 값이 설정된 적이 있다면
			if lastRaxValue != -1 {
				// 결과 목록에 추가
				results = append(results, SyscallInfo{
					Address: uint64(insn.Address), // 명령어의 주소 [1]
					Number:  lastRaxValue,
				})

				// 선택사항: syscall을 처리했으므로 lastRaxValue를 초기화하여
				// 다음 syscall에 영향을 주지 않도록 할 수 있습니다.
				// lastRaxValue = -1
			} else {
				// rax 값이 설정되지 않았는데 syscall이 호출된 경우
				fmt.Printf("경고: 0x%x에서 rax 값이 설정되지 않은 syscall 호출 발견\n", insn.Address)
			}
		}
	}

	return results, nil
}
