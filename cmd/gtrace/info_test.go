package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestInfoCommand_RequiresArgument(t *testing.T) {
	cmd := NewInfoCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error when no argument provided")
	}
}

func TestInfoCommand_RejectsExtraArguments(t *testing.T) {
	cmd := NewInfoCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"8.8.8.8", "1.1.1.1"})

	err := cmd.Execute()

	if err == nil {
		t.Error("expected error with extra arguments")
	}
}

func TestInfoCommand_IPv4IPv6MutuallyExclusive(t *testing.T) {
	cmd := NewInfoCmd()
	buf := new(bytes.Buffer)
	cmd.SetOut(buf)
	cmd.SetErr(buf)
	cmd.SetArgs([]string{"-4", "-6", "8.8.8.8"})

	err := cmd.Execute()

	if err == nil {
		t.Fatal("expected error when -4 and -6 both set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("expected mutual exclusivity error, got: %v", err)
	}
}

func TestInfoCommand_HasJsonFlag(t *testing.T) {
	cmd := NewInfoCmd()

	flag := cmd.Flags().Lookup("json")
	if flag == nil {
		t.Fatal("expected --json flag to be defined")
	}
	if flag.DefValue != "false" {
		t.Errorf("expected --json default to be false, got %s", flag.DefValue)
	}
}

func TestInfoCommand_HasIPv4Flag(t *testing.T) {
	cmd := NewInfoCmd()

	flag := cmd.Flags().ShorthandLookup("4")
	if flag == nil {
		t.Fatal("expected -4 flag to be defined")
	}
}

func TestInfoCommand_HasIPv6Flag(t *testing.T) {
	cmd := NewInfoCmd()

	flag := cmd.Flags().ShorthandLookup("6")
	if flag == nil {
		t.Fatal("expected -6 flag to be defined")
	}
}

func TestInfoResult_JSONMarshaling(t *testing.T) {
	result := InfoResult{
		IP:        "8.8.8.8",
		Hostname:  "dns.google",
		ASN:       15169,
		ASName:    "GOOGLE",
		Prefix:    "8.8.8.0/24",
		Country:   "US",
		Registry:  "arin",
		Allocated: "2023-12-28",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal InfoResult: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if parsed["ip"] != "8.8.8.8" {
		t.Errorf("expected ip=8.8.8.8, got %v", parsed["ip"])
	}
	if parsed["hostname"] != "dns.google" {
		t.Errorf("expected hostname=dns.google, got %v", parsed["hostname"])
	}
	if parsed["as_name"] != "GOOGLE" {
		t.Errorf("expected as_name=GOOGLE, got %v", parsed["as_name"])
	}
	if parsed["prefix"] != "8.8.8.0/24" {
		t.Errorf("expected prefix=8.8.8.0/24, got %v", parsed["prefix"])
	}
	// ASN should be a number
	if parsed["asn"] != float64(15169) {
		t.Errorf("expected asn=15169, got %v", parsed["asn"])
	}
}

func TestInfoResult_JSONOmitsEmptyFields(t *testing.T) {
	result := InfoResult{
		IP: "192.168.1.1",
	}

	data, err := json.Marshal(result)
	if err != nil {
		t.Fatalf("failed to marshal InfoResult: %v", err)
	}

	var parsed map[string]interface{}
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}

	if _, ok := parsed["hostname"]; ok {
		t.Error("expected hostname to be omitted when empty")
	}
	if _, ok := parsed["as_name"]; ok {
		t.Error("expected as_name to be omitted when empty")
	}
	if _, ok := parsed["prefix"]; ok {
		t.Error("expected prefix to be omitted when empty")
	}
}

func TestFormatInfoText_FullResult(t *testing.T) {
	result := InfoResult{
		IP:        "8.8.8.8",
		Hostname:  "dns.google",
		ASN:       15169,
		ASName:    "GOOGLE",
		Prefix:    "8.8.8.0/24",
		Country:   "US",
		Registry:  "arin",
		Allocated: "2023-12-28",
	}

	output := formatInfoText(result)

	expectedFields := []string{
		"IP Address", "8.8.8.8",
		"Hostname", "dns.google",
		"AS Number", "AS15169",
		"AS Name", "GOOGLE",
		"Prefix", "8.8.8.0/24",
		"Country", "US",
		"Registry", "arin",
		"Allocated", "2023-12-28",
	}

	for _, field := range expectedFields {
		if !strings.Contains(output, field) {
			t.Errorf("expected output to contain %q, got:\n%s", field, output)
		}
	}
}

func TestFormatInfoText_PartialResult(t *testing.T) {
	result := InfoResult{
		IP:  "192.168.1.1",
		ASN: 0,
	}

	output := formatInfoText(result)

	if !strings.Contains(output, "IP Address") {
		t.Errorf("expected output to contain IP Address, got:\n%s", output)
	}
	if !strings.Contains(output, "192.168.1.1") {
		t.Errorf("expected output to contain 192.168.1.1, got:\n%s", output)
	}
	// Should not contain AS Number line when ASN is 0
	if strings.Contains(output, "AS Number") {
		t.Errorf("expected no AS Number for zero ASN, got:\n%s", output)
	}
}

func TestFormatInfoText_AlignedColumns(t *testing.T) {
	result := InfoResult{
		IP:       "8.8.8.8",
		Hostname: "dns.google",
		ASN:      15169,
		ASName:   "GOOGLE",
	}

	output := formatInfoText(result)
	lines := strings.Split(strings.TrimSpace(output), "\n")

	// All lines should have " : " separator with consistent alignment
	for _, line := range lines {
		if !strings.Contains(line, " : ") {
			t.Errorf("expected line to contain ' : ' separator, got: %q", line)
		}
	}
}
