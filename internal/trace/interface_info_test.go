package trace

import (
	"net"
	"testing"

	"github.com/hervehildenbrand/gtrace/pkg/hop"
)

func TestParseInterfaceInfo_NameOnly(t *testing.T) {
	// Class 2, C-Type: bit 1 set (ifName present), role=incoming (bit 2 clear)
	// C-Type = 0b00000010 = 2
	ifName := "GigabitEthernet0/1"
	nameLen := len(ifName)

	// Build sub-object: 1 byte length + name bytes (padded to 4-byte boundary)
	paddedLen := (nameLen + 1 + 3) & ^3 // +1 for length byte, round up to 4
	subObj := make([]byte, paddedLen)
	subObj[0] = byte(nameLen)
	copy(subObj[1:], ifName)

	// Object header: length (2) + class=2 (1) + c-type (1)
	objLen := 4 + len(subObj)
	obj := make([]byte, objLen)
	obj[0] = byte(objLen >> 8)
	obj[1] = byte(objLen)
	obj[2] = 2 // class = 2 (Interface Information)
	obj[3] = 2 // c-type: bit 1 = ifName present
	copy(obj[4:], subObj)

	// Extension header: version=2 (upper nibble) + reserved + checksum
	ext := make([]byte, 4+len(obj))
	ext[0] = 0x20 // version 2
	copy(ext[4:], obj)

	result := ParseICMPExtensions(ext)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.InterfaceInfo == nil {
		t.Fatal("expected InterfaceInfo to be parsed")
	}
	if result.InterfaceInfo.Name != ifName {
		t.Errorf("expected name %q, got %q", ifName, result.InterfaceInfo.Name)
	}
}

func TestParseInterfaceInfo_IPOnly(t *testing.T) {
	// Class 2, C-Type: bit 0 set (ifAddress present)
	// C-Type = 0b00000001 = 1
	ip := net.IPv4(10, 0, 0, 1)

	// Sub-object: AFI (2 bytes, IPv4=1) + IP (4 bytes) = 8 bytes (padded)
	subObj := make([]byte, 8)
	subObj[0] = 0 // AFI high byte
	subObj[1] = 1 // AFI=1 (IPv4)
	copy(subObj[4:], ip.To4())

	objLen := 4 + len(subObj)
	obj := make([]byte, objLen)
	obj[0] = byte(objLen >> 8)
	obj[1] = byte(objLen)
	obj[2] = 2 // class = 2
	obj[3] = 1 // c-type: bit 0 = ifAddress
	copy(obj[4:], subObj)

	ext := make([]byte, 4+len(obj))
	ext[0] = 0x20
	copy(ext[4:], obj)

	result := ParseICMPExtensions(ext)
	if result == nil || result.InterfaceInfo == nil {
		t.Fatal("expected InterfaceInfo")
	}
	if !result.InterfaceInfo.IP.Equal(ip) {
		t.Errorf("expected IP %v, got %v", ip, result.InterfaceInfo.IP)
	}
}

func TestParseInterfaceInfo_WithRole(t *testing.T) {
	// C-Type: bit 2 set (outgoing role) + bit 1 (name)
	// C-Type = 0b00000110 = 6
	ifName := "eth0"
	nameLen := len(ifName)
	paddedLen := (nameLen + 1 + 3) & ^3
	subObj := make([]byte, paddedLen)
	subObj[0] = byte(nameLen)
	copy(subObj[1:], ifName)

	objLen := 4 + len(subObj)
	obj := make([]byte, objLen)
	obj[0] = byte(objLen >> 8)
	obj[1] = byte(objLen)
	obj[2] = 2
	obj[3] = 6 // bits 1+2: name + outgoing
	copy(obj[4:], subObj)

	ext := make([]byte, 4+len(obj))
	ext[0] = 0x20
	copy(ext[4:], obj)

	result := ParseICMPExtensions(ext)
	if result == nil || result.InterfaceInfo == nil {
		t.Fatal("expected InterfaceInfo")
	}
	if result.InterfaceInfo.Name != ifName {
		t.Errorf("expected name %q, got %q", ifName, result.InterfaceInfo.Name)
	}
	if result.InterfaceInfo.Role != "outgoing" {
		t.Errorf("expected role 'outgoing', got %q", result.InterfaceInfo.Role)
	}
}

func TestParseICMPExtensions_MPLSAndInterfaceInfo(t *testing.T) {
	// Build MPLS object (class 1)
	mplsEntry := []byte{0x00, 0x01, 0x01, 0x40} // Label=0, Exp=0, S=1, TTL=64
	mplsObjLen := 4 + len(mplsEntry)
	mplsObj := make([]byte, mplsObjLen)
	mplsObj[0] = byte(mplsObjLen >> 8)
	mplsObj[1] = byte(mplsObjLen)
	mplsObj[2] = 1 // class = 1 (MPLS)
	mplsObj[3] = 1 // c-type = 1
	copy(mplsObj[4:], mplsEntry)

	// Build Interface Info object (class 2)
	ifName := "lo0"
	nameLen := len(ifName)
	paddedLen := (nameLen + 1 + 3) & ^3
	subObj := make([]byte, paddedLen)
	subObj[0] = byte(nameLen)
	copy(subObj[1:], ifName)
	ifObjLen := 4 + len(subObj)
	ifObj := make([]byte, ifObjLen)
	ifObj[0] = byte(ifObjLen >> 8)
	ifObj[1] = byte(ifObjLen)
	ifObj[2] = 2
	ifObj[3] = 2 // name only
	copy(ifObj[4:], subObj)

	// Combine
	ext := make([]byte, 4+len(mplsObj)+len(ifObj))
	ext[0] = 0x20
	copy(ext[4:], mplsObj)
	copy(ext[4+len(mplsObj):], ifObj)

	result := ParseICMPExtensions(ext)
	if result == nil {
		t.Fatal("expected result")
	}
	if len(result.MPLS) == 0 {
		t.Error("expected MPLS labels")
	}
	if result.InterfaceInfo == nil {
		t.Fatal("expected InterfaceInfo")
	}
	if result.InterfaceInfo.Name != ifName {
		t.Errorf("expected name %q, got %q", ifName, result.InterfaceInfo.Name)
	}
}

func TestParseICMPExtensions_NoClass2(t *testing.T) {
	// MPLS only, no interface info
	mplsEntry := []byte{0x00, 0x01, 0x01, 0x40}
	mplsObjLen := 4 + len(mplsEntry)
	mplsObj := make([]byte, mplsObjLen)
	mplsObj[0] = byte(mplsObjLen >> 8)
	mplsObj[1] = byte(mplsObjLen)
	mplsObj[2] = 1
	mplsObj[3] = 1
	copy(mplsObj[4:], mplsEntry)

	ext := make([]byte, 4+len(mplsObj))
	ext[0] = 0x20
	copy(ext[4:], mplsObj)

	result := ParseICMPExtensions(ext)
	if result == nil {
		t.Fatal("expected result")
	}
	if len(result.MPLS) == 0 {
		t.Error("expected MPLS labels")
	}
	if result.InterfaceInfo != nil {
		t.Error("expected nil InterfaceInfo")
	}
}

func TestParseICMPExtensions_TooShort(t *testing.T) {
	result := ParseICMPExtensions([]byte{0x20, 0x00})
	if result != nil {
		t.Error("expected nil for too-short data")
	}
}

func TestInterfaceInfo_Struct(t *testing.T) {
	info := &hop.InterfaceInfo{
		Name: "GigabitEthernet0/1",
		IP:   net.ParseIP("10.0.0.1"),
		Role: "incoming",
	}
	if info.Name != "GigabitEthernet0/1" {
		t.Error("unexpected name")
	}
}
