	package static_analyzer

	import (
		"os"
		"testing"
	)

	// string 슬라이스에 특정 요소가 포함되어 있는지 확인하는 헬퍼 함수입니다.
	func contains(slice []string, item string) bool {
		for _, s := range slice {
			if s == item {
				return true
			}
		}
		return false
	}

	// "Happy Path" 테스트: 유효한 ELF 파일을 성공적으로 분석하는 경우를 검증합니다.
	func TestAnalyzeFile_Success(t *testing.T) {
		// 1. 준비 (Arrange)
		// 테스트를 위해 미리 컴파일해둔 C 애플리케이션 바이너리 경로입니다.
		testBinaryPath := "./testdata/test" 

		// 테스트 바이너리가 존재하는지 먼저 확인합니다. 없다면 테스트를 진행할 수 없습니다.
		if _, err := os.Stat(testBinaryPath); os.IsNotExist(err) {
			t.Fatalf("테스트 바이너리 '%s'를 찾을 수 없습니다. 'gcc -o test_app test_app.c' 명령으로 먼저 컴파일해주세요.", testBinaryPath)
		}

		// 2. 실행 (Act)
		// 메인 분석 함수를 호출합니다.
		report, err := AnalyzeFile(testBinaryPath)

		// 3. 검증 (Assert)
		if err != nil {
			t.Fatalf("AnalyzeFile 실행 중 예상치 못한 에러가 발생했습니다: %v", err)
		}

		if report == nil {
			t.Fatal("분석 결과(report)가 nil이면 안 됩니다.")
		}

		// SHA256 해시가 정상적으로 계산되었는지 확인합니다.
		if report.SHA256 == "" {
			t.Error("SHA256 해시가 비어있습니다.")
		}
		t.Logf("계산된 SHA256: %s", report.SHA256)

		// Imported Functions 목록에 'printf'가 포함되어 있는지 확인합니다.
		expectedFunc := "printf"
		if !contains(report.ImportedFunctions, expectedFunc) {
			t.Errorf("Imported functions 목록에 '%s'가 포함되어야 합니다. 전체 목록: %v", expectedFunc, report.ImportedFunctions)
		}

		// Possible File Paths 목록에 '/tmp/test.log'가 포함되어 있는지 확인합니다.
		expectedPath := "/tmp/test.log"
		if !contains(report.PossibleFilePaths, expectedPath) {
			t.Errorf("Possible file paths 목록에 '%s'가 포함되어야 합니다. 전체 목록: %v", expectedPath, report.PossibleFilePaths)
		}

		t.Log("ELF 파일 분석 성공: Imported functions와 file paths를 정상적으로 추출했습니다.")
	}

	// 엣지 케이스 테스트: 존재하지 않는 파일을 분석하려는 경우 에러를 반환하는지 확인합니다.
	func TestAnalyzeFile_FileNotFound(t *testing.T) {
		// 1. 준비 & 2. 실행
		// 존재하지 않는 파일 경로로 분석을 시도합니다.
		_, err := AnalyzeFile("non_existent_binary_file")

		// 3. 검증
		// 에러가 반드시 발생해야 합니다.
		if err == nil {
			t.Fatal("존재하지 않는 파일에 대해 에러가 발생해야 하지만, nil을 반환했습니다.")
		}

		t.Logf("예상대로 '파일 없음' 에러를 정상적으로 반환했습니다: %v", err)
	}

