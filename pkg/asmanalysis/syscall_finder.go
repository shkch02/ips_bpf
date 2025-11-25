package asmanalysis

//역어셈 구조체 설명
//https://github.com/knightsc/gapstone/blob/master/x86_decomposer.go

import (
	"fmt"

	"github.com/knightsc/gapstone"
)

// SyscallInfo는 발견된 시스템 콜의 정보를 담는 구조체입니다.
type SyscallInfo struct {
	Address uint64 // syscall 명령어의 주소
	Number  int64  // 호출 시점의 rax 값 (시스템 콜 번호)
}

// FindAllSyscalls는 디스셈블된 명령어 목록(함수 코드)을 순방향으로 스캔하여
// 모든 'syscall' 명령어와 그 시점의 '%rax' 레지스터 값을 찾아 슬라이스로 반환합니다.
func FindAllSyscalls(instructions []gapstone.Instruction) ([]SyscallInfo, error) {
	var results []SyscallInfo

	// rax 레지스터의 마지막 값을 추적하기 위한 변수.
	// -1은 아직 rax 값이 설정된 적 없음을 의미하는 초기값.
	lastRaxValue := int64(-1)

	for _, insn := range instructions {
		// X86 관련 정보가 없는 명령어 방어코드
		if insn.X86 == nil {
			continue
		}

		// --- 1. %rax 값 추적 ---
		// 1-1. 'mov rax, 0xN' 또는 'mov eax, 0xN' 패턴 찾기
		if insn.Mnemonic == "mov" && len(insn.X86.Operands) == 2 {
			op0 := insn.X86.Operands[0]
			op1 := insn.X86.Operands[1]

			isRaxEax := op0.Type == gapstone.X86_OP_REG &&
				(op0.Reg == gapstone.X86_REG_RAX || op0.Reg == gapstone.X86_REG_EAX)
			isImm := op1.Type == gapstone.X86_OP_IMM // 즉시값(Immediate value)

			if isRaxEax && isImm {
				lastRaxValue = op1.Imm
			}
		}

		// 1-2. 'xor eax, eax' 패턴 찾기
		if insn.Mnemonic == "xor" && len(insn.X86.Operands) == 2 {
			op0 := insn.X86.Operands[0]
			op1 := insn.X86.Operands[1]

			isEax := op0.Type == gapstone.X86_OP_REG && op0.Reg == gapstone.X86_REG_EAX
			isSame := op1.Type == gapstone.X86_OP_REG && op1.Reg == gapstone.X86_REG_EAX

			if isEax && isSame {
				lastRaxValue = 0 // 'xor eax, eax'는 0을 의미
			}
		}

		// --- 2. 'syscall' 명령어 탐지 ---
		// (기존의 복잡한 call 추적 로직 대신 'syscall' 니모닉만 확인)
		if insn.Mnemonic == "syscall" {
			// syscall을 찾았을 때, 이전에 rax 값이 설정된 적이 있다면
			if lastRaxValue != -1 {
				// 결과 목록에 추가
				results = append(results, SyscallInfo{
					Address: uint64(insn.Address),
					Number:  lastRaxValue,
				})
				// lastRaxValue를 초기화하지 않습니다.
				// (동일한 rax 값으로 여러 syscall을 호출하는 패턴이 있을 수 있으므로)
			} else {
				// rax 값이 설정되지 않았는데 syscall이 호출된 경우
				// (예: 함수 초입에서 rax가 설정되고 분기 없이 바로 syscall)
				// 추적 실패를 나타내는 값을 넣습니다.
				results = append(results, SyscallInfo{
					Address: uint64(insn.Address),
					Number:  -1, // -1은 추적 실패를 의미
				})
				fmt.Printf("경고: 0x%x에서 rax 값이 설정되지 않은 syscall 호출 발견\n", insn.Address)
			}
		}
	}
	return results, nil // result에는 시스콜 호출 주소하고 호출시 rax 인자값들어있음
}
