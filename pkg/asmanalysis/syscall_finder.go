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

// *** 추출 불가, 추후 어셈블 분석시 활용위해 남겨둠, ***
//FIXME : rax 추적 로직 개선 필요, 현재는 단순 mov 즉시값 대입과 xor eax, eax 패턴만 추적

// FindSyscalls는 디스어셈블된 명령어 목록에서 call 0x시스템콜 주소 호출하는 명령어 찾아 해당 명령어의 실행시의 eax(또는 rax) 값을 추적하여 시스템 콜 번호를 반환
func FindSyscalls(SyscallAddr uint64, instructions []gapstone.Instruction) ([]SyscallInfo, error) {
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
		//fmt.Printf("디버깅용 출력:insn.Address%x", insn.Address)
		//fmt.Println("디버깅용 출력:insn.Mnemonic", insn.Mnemonic)
		//fmt.Printf("디버깅용 출력:insn.OpStr의 실제 값: s : [%s] , +v : [%+v] ,v : [%v] \n", insn.OpStr, insn.OpStr, insn.OpStr)
		/*fmt.Println("op0:", insn.X86.Operands[0])
		fmt.Println("op1:", insn.X86.Operands[1])
		fmt.Println("OPerands", insn.X86.Operands)
		fmt.Println("Mnemonic", insn.Mnemonic)*/

		// 1-1. 'mov rax, 0xN' 또는 'mov eax, 0xN' 패턴 찾기, 메모리 조회하여 값을 가져오는 패턴은 무시 ,
		if insn.Mnemonic == "mov" && len(insn.X86.Operands) == 2 &&
			insn.X86.Operands[0].Type == gapstone.X86_OP_REG && //.Type 비교연산을 1이 아니라 gapstone.X86_OP_REG 바꾸는게 낫다고함,,
			(insn.X86.Operands[0].Reg == gapstone.X86_REG_RAX || insn.X86.Operands[0].Reg == gapstone.X86_REG_EAX) &&
			insn.X86.Operands[1].Type == 2 {

			// rax나 eax에서 두번째 피연산자가 즉시값(Imm)인 경우 해당 값 저장(아마 시스템콜 인덱스일것)
			lastRaxValue = insn.X86.Operands[1].Imm
			//fmt.Printf("디버깅용 출력:rax or eax에 있는 즉시값 가져옴, 값: %d\n", lastRaxValue)

		}

		// 1-2. 'xor eax, eax' 패턴 찾기
		if insn.Mnemonic == "xor" &&
			len(insn.X86.Operands) == 2 &&
			insn.X86.Operands[0].Reg == gapstone.X86_REG_EAX &&
			insn.X86.Operands[1].Reg == gapstone.X86_REG_EAX {
			//read 시스템콜임
			//fmt.Println("디버깅용 출력:rax or eax에 0 대입, read 시스템콜임")
			lastRaxValue = 0
		}
		// --- 2. syscall 명령어 탐지 ---

		var indirectcall bool = (SyscallAddr == uint64(insn.Address)+uint64(insn.X86.Operands[0].Mem.Disp)+6)
		var directcall bool = false
		var iscall bool = (insn.Mnemonic == "call")

		//디버그
		//fmt.Println("디버깅용 출력: SyscallAddr", SyscallAddr, " unit64(insn.Address): ", uint64(insn.Address), " uint64(insn.X86.Operands[0].Mem.Disp): ", uint64(insn.X86.Operands[0].Mem.Disp), " 합: ", uint64(insn.Address)+uint64(insn.X86.Operands[0].Mem.Disp)+6)
		//var ifBool bool = (iscall && indirectcall) || directcall
		//fmt.Printf("ifBool : %t indirectacll %t iscall %t\n",ifBool,indirectcall,iscall)

		if (iscall && indirectcall) || directcall {
			// syscall을 찾았을 때, 이전에 rax 값이 설정된 적이 있다면
			if lastRaxValue != -1 {
				// 결과 목록에 추가
				results = append(results, SyscallInfo{
					Address: uint64(insn.Address), // 명령어의 주소 [1]
					Number:  lastRaxValue,
				})
				//fmt.Println("디버깅용 출력: SyscallAddr", SyscallAddr, " unit64(insn.Address): ", uint64(insn.Address), " uint64(insn.X86.Operands[0].Mem.Disp): ", uint64(insn.X86.Operands[0].Mem.Disp), "  합: ", uint64(insn.Address)+uint64(insn.X86.Operands[0].Mem.Disp)+6)
				//fmt.Println("syscall 인덱스 Number:",  lastRaxValue)
				// 선택사항: syscall을 처리했으므로 lastRaxValue를 초기화하여
				// 다음 syscall에 영향을 주지 않도록 할 수 있습니다.
				// lastRaxValue = -1
			} else {
				// rax 값이 설정되지 않았는데 syscall이 호출된 경우
				fmt.Printf("경고: 0x%x에서 rax 값이 설정되지 않은 syscall 호출 발견\n", insn.Address)
			}
		}
		//fmt.Println("디버깅용출력 result: ",results)
	}
	return results, nil
}
