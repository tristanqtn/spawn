package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// test/VALIDATION.md claims to say, feature by feature, what is tested. A document
// like that is only worth reading if it cannot fall behind the code, so this fails
// when a test is missing from it -- or when it names a test that no longer exists.
func TestValidationMatrixIsComplete(t *testing.T) {
	doc, err := os.ReadFile(filepath.Join("test", "VALIDATION.md"))
	if err != nil {
		t.Fatal(err)
	}
	matrix := string(doc)

	files, err := filepath.Glob("*_test.go")
	if err != nil {
		t.Fatal(err)
	}
	funcRe := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	found := map[string]bool{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range funcRe.FindAllStringSubmatch(string(b), -1) {
			found[m[1]] = true
		}
	}
	if len(found) < 80 {
		t.Fatalf("only found %d tests; the scan is wrong", len(found))
	}

	for name := range found {
		// This test documenting itself would be noise.
		if name == "TestValidationMatrixIsComplete" {
			continue
		}
		if !strings.Contains(matrix, "`"+name+"`") {
			t.Errorf("%s is not in test/VALIDATION.md, so the matrix is incomplete", name)
		}
	}
	// And the reverse: a matrix naming a test that was deleted or renamed is worse
	// than one that is merely out of date, because it reads as coverage that is gone.
	for _, m := range regexp.MustCompile("`(Test[A-Za-z0-9_]+)`").FindAllStringSubmatch(matrix, -1) {
		if !found[m[1]] {
			t.Errorf("test/VALIDATION.md names %s, which no longer exists", m[1])
		}
	}
	// The scripted suites are part of the story and must stay listed.
	for _, s := range []string{"test/vpn-datapath.sh", "test/agent-loop.py"} {
		if !strings.Contains(matrix, s) {
			t.Errorf("the matrix does not mention %s", s)
		}
		if _, err := os.Stat(s); err != nil {
			t.Errorf("%s is listed but missing: %v", s, err)
		}
	}
}
