// SPDX-FileCopyrightText: 2026 Bonial International GmbH
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"testing"
)

func TestCLI_StdoutOutput(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"--author", "test-author",
		"--product", "pkg:oci/my-image",
		"--no-catalog",
	)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		t.Fatalf("command failed: %v\nstderr: %s", err, stderr.String())
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("output is not valid JSON: %v\noutput: %s", err, stdout.String())
	}

	if doc["author"] != "test-author" {
		t.Errorf("expected author test-author, got %v", doc["author"])
	}

	statements, ok := doc["statements"].([]interface{})
	if !ok {
		t.Fatalf("statements is not an array: %v", doc["statements"])
	}

	// Should have 2 statements (3rd entry is expired)
	if len(statements) != 2 {
		t.Fatalf("expected 2 statements, got %d", len(statements))
	}
}

func TestCLI_FileOutput(t *testing.T) {
	buildBinary(t)

	outFile := t.TempDir() + "/output.json"
	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "testdata/trivyignore_integration.yaml",
		"-o", outFile,
		"--author", "test-author",
		"--no-catalog",
	)

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	data, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatalf("could not read output file: %v", err)
	}

	var doc map[string]interface{}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("output file is not valid JSON: %v", err)
	}
}

func TestCLI_MissingInput(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex",
		"-i", "nonexistent.yaml",
		"--no-catalog",
	)
	err := cmd.Run()
	if err == nil {
		t.Fatal("expected error for missing input file")
	}

	exitErr, ok := err.(*exec.ExitError)
	if !ok {
		t.Fatalf("expected ExitError, got %T", err)
	}
	if exitErr.ExitCode() != 1 {
		t.Errorf("expected exit code 1, got %d", exitErr.ExitCode())
	}
}

func TestCLI_Version(t *testing.T) {
	buildBinary(t)

	cmd := exec.Command("./trivyignore-to-vex", "-v")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		t.Fatalf("command failed: %v", err)
	}

	if stdout.Len() == 0 {
		t.Error("expected version output")
	}
}

func buildBinary(t *testing.T) {
	t.Helper()
	cmd := exec.Command("go", "build", "-o", "trivyignore-to-vex", ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
}
