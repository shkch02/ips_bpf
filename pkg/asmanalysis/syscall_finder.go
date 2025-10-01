package asmanalysis

import (
	"fmt"

	"github.com/knightsc/gapstone"
)

// SyscallInfo는 발견된 시스템 콜의 정보를 담는 구조체입니다.
type SyscallInfo struct {
	Address uint64 // syscall 명령어의 주소
	Number  int64  // 호출 시점의 rax 값 (시스템 콜 번호)
}

// FindSyscalls는 디스어셈블된 명령어 목록을 분석하여 시스템 콜 호출을 찾습니다.
func FindSyscalls(instructions []gapstone.Instruction) ([]SyscallInfo, error) {
	var results []SyscallInfo

	// rax 레지스터의 마지막 값을 추적하기 위한 변수.
	// -1은 아직 rax 값이 설정된 적 없음을 의미하는 초기값.
	lastRaxValue := int64(-1)

	for _, insn := range instructions {
		// --- 1. rax 값 추적 ---
		// 예시: mov rax, 0x1 / mov eax, 0x1
		if insn.Mnemonic == "mov" && len(insn.Operands) == 2 {
			op0, op1 := insn.Operands[0], insn.Operands[1]
			// 첫 번째 피연산자가 rax 또는 eax 레지스터이고,
			if op0.Type == gapstone.CS_OP_REG && (op0.Reg == gapstone.X86_REG_RAX || op0.Reg == gapstone.X86_REG_EAX) {
				// 두 번째 피연산자가 즉시값(숫자)이면, 그 값을 저장.
				if op1.Type == gapstone.CS_OP_IMM {
					lastRaxValue = op1.Imm
				}
			}
		}

		// 예시: xor eax, eax
		if insn.Mnemonic == "xor" && len(insn.Operands) == 2 {
			op0, op1 := insn.Operands[0], insn.Operands[1]
			// 두 피연산자가 모두 eax 레지스터이면, rax는 0이 됨.
			if op0.Type == gapstone.CS_OP_REG && op0.Reg == gapstone.X86_REG_EAX &&
				op1.Type == gapstone.CS_OP_REG && op1.Reg == gapstone.X86_REG_EAX {
				lastRaxValue = 0
			}
		}

		// --- 2. syscall 명령어 탐지 ---
		if insn.Mnemonic == "syscall" {
			// syscall을 찾았을 때, 이전에 rax 값이 설정된 적이 있다면
			if lastRaxValue != -1 {
				// 결과 목록에 추가
				results = append(results, SyscallInfo{
					Address: insn.Address,
					Number:  lastRaxValue,
				})
			} else {
				// rax 값이 설정되지 않았는데 syscall이 호출된 경우 (매우 드묾)
				fmt.Printf("경고: 0x%x에서 rax 값이 설정되지 않은 syscall 호출 발견\n", insn.Address)
			}
		}
	}

	return results, nil
}
