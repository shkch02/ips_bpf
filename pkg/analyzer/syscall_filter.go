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
	//https://patorjk.com/software/taag/
	//Big 글꼴 사용
	fmt.Println()
	fmt.Println(`                  %%@@@@@@@@%       %@@@@@@@@@&    `)
	fmt.Println(`                @@@@@@@@@@@@@@@  %@@@@@@@@@@@@@@@    ______ _      ______    _____ _        _   _                             _                    `)
	fmt.Println(`    @@@@@@@@@ %@@@@@@%@%@@@@@@@@@@@@@@%@%%@@@@@@@@  |  ____| |    |  ____|  / ____| |      | | (_)          /\               | |                   `)
	fmt.Println(`@@@@@@@@@@@@%%@@@@@%         %@@@@@@@       %@@@@@  | |__  | |    | |__    | (___ | |_ __ _| |_ _  ___     /  \   _ __   __ _| |_   _ _______ _ __ `)
	fmt.Println(`      @@@@@% %@@@@@   @@@@@@@@@@@@@@         @@@@@  |  __| | |    |  __|    \___ \| __/ _' | __| |/ __|   / /\ \ | '_ \ / _' | | | | |_  / _ \ '__|`)
	fmt.Println(`             %@@@@@   %%%%@@@@@@@@@@%       @@@@@@  | |____| |____| |       ____) | || (_| | |_| | (__   / ____ \| | | | (_| | | |_| |/ /  __/ |   `)
	fmt.Println(`             %@@@@@@%%%%%@@@@@%@@@@@@%%  @@@@@@@@   |______|______|_|      |_____/ \__\__,_|\__|_|\___| /_/    \_\_| |_|\__,_|_|\__, /___\___|_|   `)
	fmt.Println(`              @@@@@@@@@@@@@@@@  @@@@@@@@@@@@@%@@                                                                                 __/ |             `)
	fmt.Println(`                %@@@@@@@@%%       %@@@@@@@@@@%                                                                                  |___/              `)
	fmt.Println()
	fmt.Println(" [ ELF Static Analyzer Booting... ]")
	fmt.Println()

	// TODO 현재 man 2 syscalls 파싱하여 얻은 목록을 sys(#)와 tracepoint참고하여 생성래퍼함수 목록만들도록 리팩토링할 예정 for 추가 가공 없이 바로 tracepoint 후킹코드 생성가능하도록
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

func parseMan() ([]string, error) {
	fmt.Println("Parsing 'man 2 syscalls' to get the list of syscalls...")

	// 'man' 명령어의 출력이 시스템 언어 설정에 영향을 받지 않도록 로케일을 'C' (영어)로 설정
	cmd := exec.Command("man", "2", "syscalls")
	cmd.Env = append(os.Environ(), "LC_ALL=C")

	// 'man' 명령어를 실행하고 결과 저장
	output, err := cmd.Output()
	if err != nil {
		// 'man' 명령어가 없거나 'manpages-dev' 같은 패키지가 설치되지 않은 경우 에러처리
		return nil, fmt.Errorf("'man 2 syscalls' command failed. Is 'manpages-dev' (or equivalent) installed? original error: %w", err)
	}

	// 필터링할 키워드 목록 (소문자로 비교)
	// x86만 고려, 나머지 모두 제외
	excludeKeywords := []string{
		"alpha", "arc", "arm", "avr32", "blackfin", "csky", "ia-64", "m68k",
		"metag", "mips", "openrisc", "parisc", "powerpc", "risc-v", "s390",
		"sh", "sparc", "xtensa", "tile",
		"not on x86", "removed in", "deprecated",
	}

	// 중복을 피하기 위해 map을 set처럼 사용
	syscallSet := make(map[string]struct{})
	inTable := false

	// 정규표현식 미리 컴파일하고, 'syscall_name(2)' 패턴 검색
	re := regexp.MustCompile(`^\s*(\w+)\(2\)`)

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		line := scanner.Text()

		// 시스템콜 테이블 시작점
		if !inTable && strings.Contains(line, "System call") && strings.Contains(line, "Kernel") && strings.Contains(line, "Notes") {
			inTable = true
			continue
		}

		// 시스템콜 테이블 종료지점
		if inTable && strings.TrimSpace(line) == "SEE ALSO" {
			break
		}

		if inTable {
			// 빈 줄이나 테이블 구분선은 스팁
			if strings.TrimSpace(line) == "" || strings.Contains(line, "──────") {
				continue
			}

			// 정규표현식으로 시스템 콜 이름을 추출하는 부분
			matches := re.FindStringSubmatch(line)
			if matches == nil || len(matches) < 2 {
				continue
			}

			name := matches[1]
			// 시스템 콜 이름 이후의 'Notes' 부분을 추출
			notesIndex := re.FindStringIndex(line)[1]
			notes := strings.ToLower(strings.TrimSpace(line[notesIndex:]))

			// 'Notes'에 제외 키워드가 있는지 확인
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

			// 최적화: SEE ALSO까지 넘어가면서 쓸데없는 코드들이 자꾸 들어감, 그냥 xtensa까지만 하고 종료
			if name == "xtensa" {
				break
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error while scanning man page output: %w", err)
	}

	if len(syscallSet) == 0 {
		// man 페이지 파싱실패, 아래 getStatocSyscallList()목록 사용하게됨
		fmt.Println("\n[WARNING] Could not parse any valid syscalls from man page.")
	}

	// map의 키(시스템 콜 이름)를 슬라이스로 변환
	syscalls := make([]string, 0, len(syscallSet))
	for name := range syscallSet {
		syscalls = append(syscalls, name)
	}

	// 알파벳순 정렬
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

// 동적 심볼목록을 받아 그 중 시스템 콜 래퍼 함수만 필터링하여 반환하는 함수
func FilterSyscalls(symbols []string) []string {
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

// GetKernelSyscallName은 커널 시스템 콜 번호를 이름으로 변환합니다.
func GetKernelSyscallName(num int64) (string, bool) {
	name, ok := kernelSyscallNameMap[num]
	return name, ok
}

var kernelSyscallNameMap = map[int64]string{
	0:   "read",
	1:   "write",
	2:   "open",
	3:   "close",
	4:   "stat",
	5:   "fstat",
	6:   "lstat",
	7:   "poll",
	8:   "lseek",
	9:   "mmap",
	10:  "mprotect",
	11:  "munmap",
	12:  "brk",
	13:  "rt_sigaction",
	14:  "rt_sigprocmask",
	15:  "rt_sigreturn",
	16:  "ioctl",
	17:  "pread64",
	18:  "pwrite64",
	19:  "readv",
	20:  "writev",
	21:  "access",
	22:  "pipe",
	23:  "select",
	24:  "sched_yield",
	25:  "mremap",
	26:  "msync",
	27:  "mincore",
	28:  "madvise",
	29:  "shmget",
	30:  "shmat",
	31:  "shmctl",
	32:  "dup",
	33:  "dup2",
	34:  "pause",
	35:  "nanosleep",
	36:  "getitimer",
	37:  "alarm",
	38:  "setitimer",
	39:  "getpid",
	40:  "sendfile",
	41:  "socket",
	42:  "connect",
	43:  "accept",
	44:  "sendto",
	45:  "recvfrom",
	46:  "sendmsg",
	47:  "recvmsg",
	48:  "shutdown",
	49:  "bind",
	50:  "listen",
	51:  "getsockname",
	52:  "getpeername",
	53:  "socketpair",
	54:  "setsockopt",
	55:  "getsockopt",
	56:  "clone",
	57:  "fork",
	58:  "vfork",
	59:  "execve",
	60:  "exit",
	61:  "wait4",
	62:  "kill",
	63:  "uname",
	64:  "semget",
	65:  "semop",
	66:  "semctl",
	67:  "shmdt",
	68:  "msgget",
	69:  "msgsnd",
	70:  "msgrcv",
	71:  "msgctl",
	72:  "fcntl",
	73:  "flock",
	74:  "fsync",
	75:  "fdatasync",
	76:  "truncate",
	77:  "ftruncate",
	78:  "getdents",
	79:  "getcwd",
	80:  "chdir",
	81:  "fchdir",
	82:  "rename",
	83:  "mkdir",
	84:  "rmdir",
	85:  "creat",
	86:  "link",
	87:  "unlink",
	88:  "symlink",
	89:  "readlink",
	90:  "chmod",
	91:  "fchmod",
	92:  "chown",
	93:  "fchown",
	94:  "lchown",
	95:  "umask",
	96:  "gettimeofday",
	97:  "getrlimit",
	98:  "getrusage",
	99:  "sysinfo",
	100: "times",
	101: "ptrace",
	102: "getuid",
	103: "syslog",
	104: "getgid",
	105: "setuid",
	106: "setgid",
	107: "geteuid",
	108: "getegid",
	109: "setpgid",
	110: "getppid",
	111: "getpgrp",
	112: "setsid",
	113: "setreuid",
	114: "setregid",
	115: "getgroups",
	116: "setgroups",
	117: "setresuid",
	118: "getresuid",
	119: "setresgid",
	120: "getresgid",
	121: "getpgid",
	122: "setfsuid",
	123: "setfsgid",
	124: "getsid",
	125: "capget",
	126: "capset",
	127: "rt_sigpending",
	128: "rt_sigtimedwait",
	129: "rt_sigqueueinfo",
	130: "rt_sigsuspend",
	131: "sigaltstack",
	132: "utime",
	133: "mknod",
	134: "uselib",
	135: "personality",
	136: "ustat",
	137: "statfs",
	138: "fstatfs",
	139: "sysfs",
	140: "getpriority",
	141: "setpriority",
	142: "sched_setparam",
	143: "sched_getparam",
	144: "sched_setscheduler",
	145: "sched_getscheduler",
	146: "sched_get_priority_max",
	147: "sched_get_priority_min",
	148: "sched_rr_get_interval",
	149: "mlock",
	150: "munlock",
	151: "mlockall",
	152: "munlockall",
	153: "vhangup",
	154: "modify_ldt",
	155: "pivot_root",
	156: "_sysctl",
	157: "prctl",
	158: "arch_prctl",
	159: "adjtimex",
	160: "setrlimit",
	161: "chroot",
	162: "sync",
	163: "acct",
	164: "settimeofday",
	165: "mount",
	166: "umount2",
	167: "swapon",
	168: "swapoff",
	169: "reboot",
	170: "sethostname",
	171: "setdomainname",
	172: "iopl",
	173: "ioperm",
	174: "create_module",
	175: "init_module",
	176: "delete_module",
	177: "get_kernel_syms",
	178: "query_module",
	179: "quotactl",
	180: "nfsservctl",
	181: "getpmsg",
	182: "putpmsg",
	183: "afs_syscall",
	184: "tuxcall",
	185: "security",
	186: "gettid",
	187: "readahead",
	188: "setxattr",
	189: "lsetxattr",
	190: "fsetxattr",
	191: "getxattr",
	192: "lgetxattr",
	193: "fgetxattr",
	194: "listxattr",
	195: "llistxattr",
	196: "flistxattr",
	197: "removexattr",
	198: "lremovexattr",
	199: "fremovexattr",
	200: "tkill",
	201: "time",
	202: "futex",
	203: "sched_setaffinity",
	204: "sched_getaffinity",
	205: "set_thread_area",
	206: "io_setup",
	207: "io_destroy",
	208: "io_getevents",
	209: "io_submit",
	210: "io_cancel",
	211: "get_thread_area",
	212: "lookup_dcookie",
	213: "epoll_create",
	214: "epoll_ctl_old",
	215: "epoll_wait_old",
	216: "remap_file_pages",
	217: "getdents64",
	218: "set_tid_address",
	219: "restart_syscall",
	220: "semtimedop",
	221: "fadvise64",
	222: "timer_create",
	223: "timer_settime",
	224: "timer_gettime",
	225: "timer_getoverrun",
	226: "timer_delete",
	227: "clock_settime",
	228: "clock_gettime",
	229: "clock_getres",
	230: "clock_nanosleep",
	231: "exit_group",
	232: "epoll_wait",
	233: "epoll_ctl",
	234: "tgkill",
	235: "utimes",
	236: "vserver",
	237: "mbind",
	238: "set_mempolicy",
	239: "get_mempolicy",
	240: "mq_open",
	241: "mq_unlink",
	242: "mq_timedsend",
	243: "mq_timedreceive",
	244: "mq_notify",
	245: "mq_getsetattr",
	246: "kexec_load",
	247: "waitid",
	248: "add_key",
	249: "request_key",
	250: "keyctl",
	251: "ioprio_set",
	252: "ioprio_get",
	253: "inotify_init",
	254: "inotify_add_watch",
	255: "inotify_rm_watch",
	256: "migrate_pages",
	257: "openat",
	258: "mkdirat",
	259: "mknodat",
	260: "fchownat",
	261: "futimesat",
	262: "newfstatat",
	263: "unlinkat",
	264: "renameat",
	265: "linkat",
	266: "symlinkat",
	267: "readlinkat",
	268: "fchmodat",
	269: "faccessat",
	270: "pselect6",
	271: "ppoll",
	272: "unshare",
	273: "set_robust_list",
	274: "get_robust_list",
	275: "splice",
	276: "tee",
	277: "sync_file_range",
	278: "vmsplice",
	279: "move_pages",
	280: "utimensat",
	281: "epoll_pwait",
	282: "signalfd",
	283: "timerfd_create",
	284: "eventfd",
	285: "fallocate",
	286: "timerfd_settime",
	287: "timerfd_gettime",
	288: "accept4",
	289: "signalfd4",
	290: "eventfd2",
	291: "epoll_create1",
	292: "dup3",
	293: "pipe2",
	294: "inotify_init1",
	295: "preadv",
	296: "pwritev",
	297: "rt_tgsigqueueinfo",
	298: "perf_event_open",
	299: "recvmmsg",
	300: "fanotify_init",
	301: "fanotify_mark",
	302: "prlimit64",
	303: "name_to_handle_at",
	304: "open_by_handle_at",
	305: "clock_adjtime",
	306: "syncfs",
	307: "sendmmsg",
	308: "setns",
	309: "getcpu",
	310: "process_vm_readv",
	311: "process_vm_writev",
	312: "kcmp",
	313: "finit_module",
	314: "sched_setattr",
	315: "sched_getattr",
	316: "renameat2",
	317: "seccomp",
	318: "getrandom",
	319: "memfd_create",
	320: "kexec_file_load",
	321: "bpf",
	322: "execveat",
	323: "userfaultfd",
	324: "membarrier",
	325: "mlock2",
	326: "copy_file_range",
	327: "preadv2",
	328: "pwritev2",
	329: "pkey_mprotect",
	330: "pkey_alloc",
	331: "pkey_free",
	332: "statx",
	333: "io_pgetevents",
	334: "rseq",
	424: "pidfd_send_signal",
	425: "io_uring_setup",
	426: "io_uring_enter",
	427: "io_uring_register",
	428: "open_tree",
	429: "move_mount",
	430: "fsopen",
	431: "fsconfig",
	432: "fsmount",
	433: "fspick",
	434: "pidfd_open",
	435: "clone3",
	436: "close_range",
	437: "openat2",
	440: "process_madvise",
	441: "epoll_pwait2",
	442: "mount_setattr",
	443: "quotactl_fd",
	444: "landlock_create_ruleset",
	445: "landlock_add_rule",
	446: "landlock_restrict_self",
	447: "memfd_secret",
	448: "process_mrelease",
	449: "futex_waitv",
	450: "set_mempolicy_home_node",
	451: "cachestat",
	452: "fchmodat2",
	453: "map_shadow_stack",
	454: "futex_wake",
	455: "futex_wait",
	456: "futex_requeue",
	457: "statmount",
	458: "listmount",
	459: "lsm_get_self_attr",
	460: "lsm_set_self_attr",
	461: "lsm_list_modules",
}
