package trace

import "testing"

func TestExtractTransportInfo_NilOnShortData(t *testing.T) {
	result := ExtractTransportInfo(nil, 20, "tcp")
	if result != nil {
		t.Error("expected nil for nil data")
	}
	result = ExtractTransportInfo(make([]byte, 10), 20, "tcp")
	if result != nil {
		t.Error("expected nil for data shorter than IP header")
	}
}

func TestExtractTransportInfo_DSCP(t *testing.T) {
	data := make([]byte, 28)
	data[0] = 0x45
	data[1] = 0xB8          // TOS = DSCP 46 (EF) << 2 = 0xB8
	data[6] = 0x40          // DF set
	data[8] = 0x01
	data[9] = 0x06
	result := ExtractTransportInfo(data, 20, "tcp")
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.DSCP != 46 {
		t.Errorf("DSCP = %d, want 46", result.DSCP)
	}
	if result.ECN != 0 {
		t.Errorf("ECN = %d, want 0", result.ECN)
	}
}

func TestExtractTransportInfo_ECN(t *testing.T) {
	data := make([]byte, 28)
	data[0] = 0x45
	data[1] = 0x03 // DSCP 0, ECN 3 (CE)
	result := ExtractTransportInfo(data, 20, "icmp")
	if result.ECN != 3 {
		t.Errorf("ECN = %d, want 3", result.ECN)
	}
}

func TestExtractTransportInfo_DFBit(t *testing.T) {
	tests := []struct {
		name   string
		byte6  byte
		wantDF bool
	}{
		{"DF set", 0x40, true},
		{"DF clear", 0x00, false},
		{"DF set with MF", 0x60, true},
		{"MF only", 0x20, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, 28)
			data[0] = 0x45
			data[6] = tt.byte6
			result := ExtractTransportInfo(data, 20, "icmp")
			if result.DF != tt.wantDF {
				t.Errorf("DF = %v, want %v", result.DF, tt.wantDF)
			}
		})
	}
}

func TestExtractTransportInfo_TCP(t *testing.T) {
	data := make([]byte, 34) // 20 IP + 14 TCP (enough for flags)
	data[0] = 0x45
	data[20] = 0x30; data[21] = 0x39 // SrcPort = 12345
	data[22] = 0x00; data[23] = 0x50 // DstPort = 80
	data[24] = 0x00; data[25] = 0x00; data[26] = 0x00; data[27] = 0x01 // SeqNum = 1
	data[33] = 0x02 // Flags = SYN

	result := ExtractTransportInfo(data, 20, "tcp")
	if result.TCPSrcPort != 12345 {
		t.Errorf("TCPSrcPort = %d, want 12345", result.TCPSrcPort)
	}
	if result.TCPDstPort != 80 {
		t.Errorf("TCPDstPort = %d, want 80", result.TCPDstPort)
	}
	if result.TCPSeqNum != 1 {
		t.Errorf("TCPSeqNum = %d, want 1", result.TCPSeqNum)
	}
	if result.TCPFlagsStr != "SYN" {
		t.Errorf("TCPFlagsStr = %q, want %q", result.TCPFlagsStr, "SYN")
	}
}

func TestExtractTransportInfo_TCP_ShortFlags(t *testing.T) {
	data := make([]byte, 28) // Only 8 transport bytes
	data[0] = 0x45
	data[20] = 0x30; data[21] = 0x39
	data[22] = 0x00; data[23] = 0x50
	data[24] = 0x00; data[25] = 0x00; data[26] = 0x00; data[27] = 0x01

	result := ExtractTransportInfo(data, 20, "tcp")
	if result.TCPSrcPort != 12345 {
		t.Errorf("TCPSrcPort = %d, want 12345", result.TCPSrcPort)
	}
	if result.TCPFlagsStr != "" {
		t.Errorf("TCPFlagsStr = %q, want empty", result.TCPFlagsStr)
	}
}

func TestExtractTransportInfo_UDP(t *testing.T) {
	data := make([]byte, 28) // 20 IP + 8 UDP
	data[0] = 0x45
	data[20] = 0x82; data[21] = 0x9A // SrcPort = 33434
	data[22] = 0x82; data[23] = 0x9B // DstPort = 33435
	data[24] = 0x00; data[25] = 0x40 // Length = 64
	data[26] = 0xAB; data[27] = 0xCD // Checksum = 0xABCD

	result := ExtractTransportInfo(data, 20, "udp")
	if result.UDPSrcPort != 33434 {
		t.Errorf("UDPSrcPort = %d, want 33434", result.UDPSrcPort)
	}
	if result.UDPDstPort != 33435 {
		t.Errorf("UDPDstPort = %d, want 33435", result.UDPDstPort)
	}
	if result.UDPLength != 64 {
		t.Errorf("UDPLength = %d, want 64", result.UDPLength)
	}
	if result.UDPChecksum != 0xABCD {
		t.Errorf("UDPChecksum = 0x%X, want 0xABCD", result.UDPChecksum)
	}
}

func TestFormatTCPFlags(t *testing.T) {
	tests := []struct {
		flags uint8
		want  string
	}{
		{0x02, "SYN"},
		{0x12, "SYN-ACK"},
		{0x10, "ACK"},
		{0x04, "RST"},
		{0x14, "RST-ACK"},
		{0x01, "FIN"},
		{0x11, "FIN-ACK"},
		{0x18, "PSH-ACK"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := formatTCPFlags(tt.flags)
			if got != tt.want {
				t.Errorf("formatTCPFlags(0x%02X) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}
