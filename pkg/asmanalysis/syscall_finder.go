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
	fmt.Println("FindSyscalls 디버깅용 출력")
	// rax 레지스터의 마지막 값을 추적하기 위한 변수.
	// -1은 아직 rax 값이 설정된 적 없음을 의미하는 초기값.
	lastRaxValue := int64(-1)

	for _, insn := range instructions {
		// X86 관련 정보가 없는 명령어 방어코드
		//if insn.X86 == nil {
		//	fmt.Println("디버깅용 출력:,insn.X86 == nil, continue")
		//	continue
		//}

		if insn.OpStr == "" {
			continue
		}

		fmt.Println("디버깅용 출력 forloop 내부임 ---------------------") //디버깅용 출력
		//fmt.Println("디버깅용 출력:insn.Id", insn.Id)
		fmt.Println("디버깅용 출력:insn.Address", insn.Address)
		//fmt.Println("디버깅용 출력:insn.Size", insn.Size)
		//fmt.Println("디버깅용 출력:insn.Bytes", insn.Bytes)
		fmt.Println("디버깅용 출력:insn.Mnemonic", insn.Mnemonic)
		fmt.Println("디버깅용 출력:insn.OpStr", insn.OpStr)
		//fmt.Println("디버깅용 출력:insn.X86.Prefix", insn.X86.Prefix) //

		//디버깅용 출력
		// --- 1. rax 값 추적 ---
		fmt.Println("1-1분기 디버깅", insn.OpStr[0], insn.OpStr[1])
		// 1-1. mov rax, 0xN (또는 mov eax, 0xN)
		if insn.Mnemonic == "mov" && len(insn.OpStr) == 2 {
			//op0, op1 :=insn.OpStr[0], insn.OpStr[1]
			fmt.Println(insn.OpStr[0], insn.OpStr[1])
			// 첫 번째 피연산자가 rax 또는 eax 레지스터이고,
			/*if op0 == gapstone.X86_OP_REG && (op0.Reg == gapstone.X86_REG_RAX || op0.Reg == gapstone.X86_REG_EAX) {
				// 두 번째 피연산자가 즉시값(숫자)이면, 그 값을 저장.
				if op1.Type == gapstone.X86_OP_IMM {
					lastRaxValue = op1.Imm
				}
			}*/
		}
		fmt.Println("1-2분기 디버깅", insn.OpStr[0], insn.OpStr[1])
		// 1-2. xor eax, eax
		if insn.Mnemonic == "xor" && len(insn.OpStr) == 2 {
			//op0, op1 := insn.OpStr[0], insn.OpStr[1]
			fmt.Println(insn.OpStr[0], insn.OpStr[1]) //디버깅

			// 두 피연산자가 모두 eax 레지스터이면, rax는 0이 됨.
			/*if op0.Type == gapstone.X86_OP_REG && op0.Reg == gapstone.X86_REG_EAX &&
				op1.Type == gapstone.X86_OP_REG && op1.Reg == gapstone.X86_REG_EAX {
				lastRaxValue = 0
			}*/
		}

		// --- 2. syscall 명령어 탐지 ---
		if insn.Mnemonic == "syscall" {
			// syscall을 찾았을 때, 이전에 rax 값이 설정된 적이 있다면
			if lastRaxValue != -1 {
				// 결과 목록에 추가
				results = append(results, SyscallInfo{
					Address: uint64(insn.Address),
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
