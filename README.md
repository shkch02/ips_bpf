# ELF 정적 분석기

## 1.프로젝트 개요
본 프로젝트는 GoLang으로 작성된 ELF 바이너리 정적 분석 도구입니다. 리눅스 실행파일을 입력받아 해당 파일이 런타임에 의존하는 동적 심볼 목록을 추출합니다.

더 나아가, 이 심볼들이 의존하는 libc.so.6 (GNU C 라이브러리) 파일을 역어셈블하여, 래퍼 함수(예: open)가 실제로 호출하는 커널 시스템 콜 번호(예: openat, 257번)를 추적합니다.

최종 목표는 관리자가 eBPF 등에서 사용할 수 있는 실제 커널 시스템 콜 매핑을 JSON 형식으로 출력하는 것입니다.

## 2. 주요 기능
* **ELF 파일 파싱** : GoLang의 debug/elf 패키지를 사용하여 실행파일과 libc.so.6의 .dynsym, .text섹션등을 분석
  
*  **동적 심볼 추출** : 바이너리가 런타임에 의존하는 동적 심볼 목록을 추출
  
*  **시스템 콜 필터링** :  man 2 syscalls 출력을 파싱하여, 추출된 심볼 중 어떤 것이 시스템 콜 "래퍼"인지 1차 필터링합니다.

* **커널 시스템 콜 추적** : 식별된 래퍼함수에 대해 libc.so.6으 .text섹션을 역어셈블 합니다

* **EAX / RAX 값 추출** : syscall 호출 직전의 mov $NUM, %eax 또는 xor %eax, %eax 인 패턴을 분석하여 실제 커널 호출 syscall 번호를 추출합니다

*  **JSON 형식 출력** : 최종적으로 래퍼 함수 이름과 매핑된 커널 시스템 콜 번호(및 주소) 배열 (map[string][]SyscallInfo)을 JSON 형식으로 표준 출력합니다.

## 3. 요구사항
* **GoLang** : Go 1.24.3 이상 (go.mod 기준)
* **운영체제** : Linux
* **man** : man명령어 및 manpages-dev 실행가능(불가하다면 정적으로 목록 작성 가능)
* **Go 의존성** : github.com/knightsc/gapstone GoLang의 디스어셈블러

## 4. 사용 방법
#### 1. (선택) 바이너리 빌드
```bash
go build ./cmd/static-analyzer
```
를 이용하여 go소스코드를 바이너리로 빌드가능(생략가능)

#### 2. 분석기 실행
go run으로 빌드와 실행을 동시에 하거나, 빌드된 바이너리파일 실행

go run 으로 빌드와 실행 
```bash
go run ./cmd/static-analyzer/main.go <분석할_ELF_파일_경로>
```

1단계에서 빌드된 바이너리 실행
```bash
./static-analyzer <분석할_ELF_파일_경로>
```

## 5. 프로젝트 구조
```
.
├── cmd/static-analyzer/
│   └── main.go             # (메인) 프로그램 엔트리 포인트, ELF 및 Libc 분석기 호출
├── pkg/
│   ├── analyzer/
│   │   ├── elf_parser.go     # (모듈) ELF 파일 파싱, Libc 함수 바이트코드 추출 로직
│   │   └── syscall_filter.go # (모듈) man 페이지 파싱, 1차 래퍼 함수 필터링 로직
│   └── asmanalysis/
│       └── syscall_finder.go # (모듈) gapstone으로 역어셈블된 코드에서 'syscall' 및 %rax 값 추적
├── go.mod                    # Go 모듈 정의
├── go.sum                    # 의존성 록 파일
└── .vscode/
    └── launch.json           # VSCode 디버깅 설정
```

## 6. 향후 개선 사항

###
래퍼함수 목록 추출 : 현재 man 2 syscalls 파싱하여 얻은 목록을 sys(#)와 tracepoint참고하여 생성래퍼함수 목록 만들도록 리팩토링할 예정 
syscall_filter.go의 syscallSet 생성 부분 고치면됨

### 기본 매핑으로 넘어갈 부분들 
JMP 추적: open -> jmp <__open>과 같이 함수 시작 부분의 간접 점프를 따라가도록 elf_parser.go 개선.

복잡한 제어 흐름: if/else 분기에 따라 syscall 번호가 달라지는 복잡한 래퍼 함수 분석 지원.

정적 링크된 바이너리: libc가 아닌 바이너리 내부에 syscall 명령어가 직접 포함된 경우(vDSO 사용 등) 분석 지원.

### JSON에 쓸데없는값 뺴고 키밸류 형태로  redis연동 준비
## 7. 라이센스

