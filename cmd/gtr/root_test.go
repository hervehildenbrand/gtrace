package main

import (
	"bytes"
	"testing"
)

func TestRootCommand_RequiresTarget(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error when no target provided")
	}
}

func TestRootCommand_AcceptsTarget(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	// Use --dry-run to avoid actual traceroute
	cmd.SetArgs([]string{"google.com", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestRootCommand_ParsesFromFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--from", "London", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	from, _ := cmd.Flags().GetString("from")
	if from != "London" {
		t.Errorf("expected from 'London', got %q", from)
	}
}

func TestRootCommand_ParsesProtocolFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--protocol", "tcp", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	protocol, _ := cmd.Flags().GetString("protocol")
	if protocol != "tcp" {
		t.Errorf("expected protocol 'tcp', got %q", protocol)
	}
}

func TestRootCommand_ParsesPortFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--port", "443", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	port, _ := cmd.Flags().GetInt("port")
	if port != 443 {
		t.Errorf("expected port 443, got %d", port)
	}
}

func TestRootCommand_ParsesMaxHopsFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--max-hops", "20", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	maxHops, _ := cmd.Flags().GetInt("max-hops")
	if maxHops != 20 {
		t.Errorf("expected max-hops 20, got %d", maxHops)
	}
}

func TestRootCommand_ParsesCompareFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--compare", "--from", "London", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	compare, _ := cmd.Flags().GetBool("compare")
	if !compare {
		t.Error("expected compare to be true")
	}
}

func TestRootCommand_ParsesMonitorFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--monitor", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	monitor, _ := cmd.Flags().GetBool("monitor")
	if !monitor {
		t.Error("expected monitor to be true")
	}
}

func TestRootCommand_ParsesOutputFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "-o", "results.json", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	output, _ := cmd.Flags().GetString("output")
	if output != "results.json" {
		t.Errorf("expected output 'results.json', got %q", output)
	}
}

func TestRootCommand_ParsesSimpleFlag(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--simple", "--dry-run"})

	err := cmd.Execute()

	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	simple, _ := cmd.Flags().GetBool("simple")
	if !simple {
		t.Error("expected simple to be true")
	}
}

func TestRootCommand_ValidatesProtocol(t *testing.T) {
	cmd := NewRootCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"google.com", "--protocol", "invalid", "--dry-run"})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error for invalid protocol")
	}
}

func TestRootCommand_DefaultValues(t *testing.T) {
	cmd := NewRootCmd()

	protocol, _ := cmd.Flags().GetString("protocol")
	if protocol != "icmp" {
		t.Errorf("expected default protocol 'icmp', got %q", protocol)
	}

	maxHops, _ := cmd.Flags().GetInt("max-hops")
	if maxHops != 30 {
		t.Errorf("expected default max-hops 30, got %d", maxHops)
	}

	packets, _ := cmd.Flags().GetInt("packets")
	if packets != 3 {
		t.Errorf("expected default packets 3, got %d", packets)
	}
}
