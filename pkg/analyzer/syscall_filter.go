// pkg/analyzer/syscall_filter.go
package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strings"
)

// 시스템 호출 목록을 저장하기 위한 Set (map)
var syscallSet = make(map[string]struct{})

func init() {
	//proc/kallsyms에서 동적으로 시스템 콜 목록추출
	syscalls, err := parseMan()
	if err != nil {
		fmt.Fprintf(os.Stderr, "경고: /proc/kallsyms에서 시스템 콜 목록을 동적으로 로드하지 못했습니다: %v\n", err)
		fmt.Fprintln(os.Stderr, "미리 정의된 정적 시스템 콜 목록을 사용합니다.")
		syscalls = getStaticSyscallList()
	}

	// 3. 최종적으로 얻은 시스템 콜 목록으로 Set생성
	for _, s := range syscalls {
		syscallSet[s] = struct{}{}
	}
}


//이거 바꿔야함 /proc/kallsym는 커널용이고, 지금은 man 2 syscalls 파싱해서 얻어야할거같음 generate_bpf도 해당 테이블 사용함
func parseMan() ([]string, error) {
	fmt.Println("Parsing 'man 2 syscalls' to get the list of syscalls...")
	
	// 'man' 명령어의 출력이 시스템 언어 설정에 영향을 받지 않도록 로케일을 'C' (영어)로 설정합니다.
	cmd := exec.Command("man", "2", "syscalls")
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	// 'man' 명령어를 실행하고 결과를 가져옵니다.
	output, err := cmd.Output()
	if err != nil {
		// 'man' 명령어가 없거나 'manpages-dev' 같은 패키지가 설치되지 않은 경우 에러가 발생합니다.
		return nil, fmt.Errorf("'man 2 syscalls' command failed. Is 'manpages-dev' (or equivalent) installed? original error: %w", err)
	}

	// 필터링할 키워드 목록 (소문자로 비교)
	// 특정 아키텍처 전용이거나 더 이상 사용되지 않는 시스템 콜을 제외합니다.
	excludeKeywords := []string{
		"alpha", "arc", "arm", "avr32", "blackfin", "csky", "ia-64", "m68k",
		"metag", "mips", "openrisc", "parisc", "powerpc", "risc-v", "s390",
		"sh", "sparc", "xtensa", "tile",
		"not on x86", "removed in", "deprecated",
	}

	// 중복을 피하기 위해 map을 set처럼 사용합니다.
	syscallSet := make(map[string]struct{})
	inTable := false

	// 정규표현식을 미리 컴파일하여 성능을 높입니다. 'syscall_name(2)' 패턴을 찾습니다.
	re := regexp.MustCompile(`^\s*(\w+)\(2\)`)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		// 테이블 시작점을 찾습니다.
		if !inTable && strings.Contains(line, "System call") && strings.Contains(line, "Kernel") && strings.Contains(line, "Notes") {
			inTable = true
			continue
		}

		// 테이블 종료점을 찾습니다.
		if inTable && strings.TrimSpace(line) == "SEE ALSO" {
			break
		}

		if inTable {
			// 빈 줄이나 테이블 구분선은 건너뜁니다.
			if strings.TrimSpace(line) == "" || strings.Contains(line, "──────") {
				continue
			}

			// 정규표현식으로 시스템 콜 이름을 추출합니다.
			matches := re.FindStringSubmatch(line)
			if matches == nil || len(matches) < 2 {
				continue
			}

			name := matches[1]
			// 시스템 콜 이름 이후의 'Notes' 부분을 추출합니다.
			notesIndex := re.FindStringIndex(line)[1]
			notes := strings.ToLower(strings.TrimSpace(line[notesIndex:]))

			// 'Notes'에 제외 키워드가 있는지 확인합니다.
			isExcluded := false
			if notes != "" {
				for _, keyword := range excludeKeywords {
					if strings.Contains(notes, keyword) {
						isExcluded = true
						break
					}
				}
			}

			if !isExcluded {
				syscallSet[name] = struct{}{}
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning man page output: %w", err)
	}
	
	if len(syscallSet) == 0 {
		// man 페이지에서 유효한 시스템 콜을 하나도 파싱하지 못한 경우 경고를 반환할 수 있습니다.
		// 여기서는 빈 리스트와 nil 에러를 반환하여 호출자가 처리하도록 합니다.
		fmt.Println("\n[WARNING] Could not parse any valid syscalls from man page.")
	}

	// map의 키(시스템 콜 이름)를 슬라이스로 변환합니다.
	syscalls := make([]string, 0, len(syscallSet))
	for name := range syscallSet {
		syscalls = append(syscalls, name)
	}

	// 알파벳순으로 정렬합니다.
	sort.Strings(syscalls)
	
	fmt.Printf("Successfully parsed %d filtered syscalls from man page.\n", len(syscalls))
	return syscalls, nil
}


func getStaticSyscallList() []string {
	return []string{
		"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap",
		"mprotect", "munmap", "brk", "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl",
		"pread64", "pwrite64", "readv", "writev", "access", "pipe", "select", "sched_yield",
		"mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2",
		"pause", "nanosleep", "getitimer", "alarm", "setitimer", "getpid", "sendfile", "socket",
		"connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind",
		"listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt",
		"clone", "fork", "vfork", "execve", "exit", "wait4", "kill", "uname", "semget", "semop",
		"semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync",
		"fdatasync", "truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename",
		"mkdir", "rmdir", "creat", "link", "unlink", "symlink", "readlink", "chmod", "fchmod",
		"chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo",
		"times", "ptrace", "getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid",
		// 필요시 추가
	}
}

//FilterSyscalls는 추출된 다이나믹 심볼중 시스템콜만 추출하여 반환
func (a *ELFAnalyzer) FilterSyscalls(symbols []string) []string {
	// 결과를 담을 슬라이스
	foundSyscalls := make([]string, 0)

	for _, symbol := range symbols {
		// 현재 심볼이 미리 정의된 시스템 콜 Set에 있는지 확인 (O(1) 성능)
		if _, ok := syscallSet[symbol]; ok {
			foundSyscalls = append(foundSyscalls, symbol)
		}
	}
	return foundSyscalls
}