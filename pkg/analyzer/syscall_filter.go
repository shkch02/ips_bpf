// pkg/analyzer/syscall_filter.go
package analyzer

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// 시스템 호출 목록을 저장하기 위한 Set (map)
var syscallSet = make(map[string]struct{})

func init() {
	//proc/kallsyms에서 동적으로 시스템 콜 목록추출
	syscalls, err := loadSyscallsFromKallsyms()
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

func loadSyscallsFromKallsyms() ([]string, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, fmt.Errorf("'/proc/kallsyms' 파일을 열 수 없습니다: %w", err)
	}
	defer file.Close()

	var foundSyscalls []string
	scanner := bufio.NewScanner(file)

	const prefix = "__x64_sys_"

	// 파일을 한 줄씩 스캔합
	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)

		// 라인이 비어있거나 필드가 충분하지 않으면 건너뜀
		if len(fields) < 3 {
			continue
		}
		
		symbolName := fields[2]
		if strings.HasPrefix(symbolName, prefix) {// 심볼 이름이 "__x64_sys_"로 시작하는지 확인
			syscallName := strings.TrimPrefix(symbolName, prefix)// 접두사를 제거하여 순수한 시스템 콜 이름만 추출
			foundSyscalls = append(foundSyscalls, syscallName)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("파일 스캔 중 오류 발생: %w", err)
	}

	if len(foundSyscalls) == 0 {
		return nil, fmt.Errorf("'%s' 접두사를 가진 시스템 콜 심볼을 찾을 수 없습니다", prefix)
	}
	fmt.Println("디버깅용출력 /kallsyms : ",foundSyscalls)
	return foundSyscalls, nil
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