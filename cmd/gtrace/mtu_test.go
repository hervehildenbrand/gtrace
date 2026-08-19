package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestMTUCommand_RequiresTarget(t *testing.T) {
	cmd := NewMTUCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	if err := cmd.Execute(); err == nil {
		t.Error("expected error when target is missing")
	}
}

func TestMTUCommand_DryRunParses(t *testing.T) {
	cmd := NewMTUCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--dry-run"})

	if err := cmd.Execute(); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMTUCommand_RejectsTCP(t *testing.T) {
	cmd := NewMTUCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--protocol", "tcp", "--dry-run"})

	err := cmd.Execute()
	if err == nil || !strings.Contains(err.Error(), "icmp or udp") {
		t.Errorf("error = %v, want protocol rejection mentioning icmp or udp", err)
	}
}
