// elfanalyzer 패키지는 ELF 바이너리 파일을 정적으로 분석하는 기능을 제공합니다.
// 이 분석기는 외부 라이브러리 호출(잠재적 시스템 콜)과 바이너리 내에 포함된
// 문자열(잠재적 파일 경로)을 추출하는 데 중점을 둡니다.
package elfanalyzer

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
)

// AnalysisReport는 ELF 파일 정적 분석 결과를 담는 구조체입니다.
// 이 구조체는 최종적으로 정책 CRD의 'staticAnalysis' 필드를 채우는 데 사용됩니다.
type AnalysisReport struct {
	BinaryPath        string   `json:"binaryPath"`        // 분석된 바이너리의 경로
	SHA256            string   `json:"sha256"`            // 바이너리 파일의 SHA256 해시 (무결성 및 식별용)
	ImportedFunctions []string `json:"importedFunctions"` // 동적 라이브러리에서 가져오는 함수 목록
	PossibleFilePaths []string `json:"possibleFilePaths"` // 바이너리 내에서 발견된 잠재적 파일 경로 문자열
}

// AnalyzeFile은 지정된 경로의 ELF 파일을 분석하고 분석 리포트를 반환합니다.
// 이 함수가 이 패키지의 메인 진입점(Entrypoint)입니다.
func AnalyzeFile(filePath string) (*AnalysisReport, error) {
	// 1. 파일 열기
	file, err := elf.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("ELF 파일을 여는 데 실패했습니다: %w", err)
	}
	defer file.Close()

	// 2. 기본 리포트 구조체 생성
	report := &AnalysisReport{
		BinaryPath: filePath,
	}

	// 3. 파일 SHA256 해시 계산
	hash, err := calculateSHA256(filePath)
	if err != nil {
		// 해시 계산 실패가 전체 분석 실패를 의미하진 않으므로, 에러를 로깅하고 진행할 수 있습니다.
		// 여기서는 간단하게 에러를 반환합니다.
		return nil, fmt.Errorf("파일 해시 계산에 실패했습니다: %w", err)
	}
	report.SHA256 = hash

	// 4. Imported Functions 추출
	importedFuncs, err := extractImportedFunctions(file)
	if err != nil {
		return nil, fmt.Errorf("Imported function 추출에 실패했습니다: %w", err)
	}
	report.ImportedFunctions = importedFuncs

	// 5. 잠재적 파일 경로 문자열 추출
	// .rodata 섹션은 읽기 전용 데이터(주로 문자열 리터럴)를 포함하므로 주된 분석 대상입니다.
	possiblePaths := extractStringsFromSection(file.Section(".rodata"))
	report.PossibleFilePaths = possiblePaths

	return report, nil
}

// extractImportedFunctions는 ELF 파일의 동적 심볼 테이블을 읽어
// 외부 공유 라이브러리로부터 import하는 함수 목록을 추출합니다.
func extractImportedFunctions(file *elf.File) ([]string, error) {
	symbols, err := file.ImportedSymbols()
	if err != nil {
		return nil, fmt.Errorf("동적 심볼을 읽는 데 실패했습니다: %w", err)
	}

	var functions []string
	for _, sym := range symbols {
		// 함수 타입(STT_FUNC)인 심볼만 필터링하고, 이름이 비어있지 않은 경우 추가합니다.
		if elf.ST_TYPE(sym.Info) == elf.STT_FUNC && sym.Name != "" {
			functions = append(functions, sym.Name)
		}
	}

	return functions, nil
}

// extractStringsFromSection는 주어진 ELF 섹션에서 의미 있는 문자열들을 추출합니다.
// 정규표현식을 사용하여 파일 경로 또는 설정값처럼 보이는 문자열을 찾습니다.
func extractStringsFromSection(section *elf.Section) []string {
	if section == nil {
		return nil
	}

	data, err := section.Data()
	if err != nil {
		// 데이터 읽기 실패 시 빈 슬라이스 반환
		return nil
	}

	// 정규표현식: 경로, 환경 변수, 일반 설정값처럼 보이는 4자 이상의 문자열을 찾습니다.
	// 예: "/etc/nginx.conf", "USER", "error.log"
	re := regexp.MustCompile(`[a-zA-Z0-9\/._-]{4,}`)
	matches := re.FindAllString(string(data), -1)

	// 중복 제거
	uniqueMatches := make(map[string]struct{})
	for _, s := range matches {
		uniqueMatches[s] = struct{}{}
	}

	result := make([]string, 0, len(uniqueMatches))
	for s := range uniqueMatches {
		result = append(result, s)
	}

	return result
}

// calculateSHA256는 파일의 SHA256 해시를 계산하여 16진수 문자열로 반환합니다.
func calculateSHA256(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}