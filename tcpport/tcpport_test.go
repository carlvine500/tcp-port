package tcpport

import (
	"testing"
)

func TestWildcardMatch(t *testing.T) {
	tests := []struct {
		s, p string
		want bool
	}{
		{"test", "test", true},
		{"test", "tes*", true},
		{"test", "tes?", true},
		{"test", "t*", true},
		{"test", "*t*", true},
		{"test", "tt*", false},
		{"test", "es", false},
		{"com.example.DemoService", "com.example.*", true},
		{"com.example.DemoService", "*.DemoService", true},
		{"", "*", true},
	}
	for _, tt := range tests {
		got := WildcardMatch(tt.s, tt.p)
		if got != tt.want {
			t.Errorf("WildcardMatch(%q, %q) = %v, want %v", tt.s, tt.p, got, tt.want)
		}
	}
}

func TestEndpointString(t *testing.T) {
	e := Endpoint{IP: "10.0.0.1", Port: 6379}
	if s := e.String(); s != "10.0.0.1:6379" {
		t.Errorf("String() = %s, want 10.0.0.1:6379", s)
	}
}

func TestEndpointEquals(t *testing.T) {
	a := Endpoint{IP: "10.0.0.1", Port: 80}
	b := Endpoint{IP: "10.0.0.1", Port: 80}
	c := Endpoint{IP: "10.0.0.2", Port: 80}
	if !a.Equals(b) {
		t.Error("a should equal b")
	}
	if a.Equals(c) {
		t.Error("a should not equal c")
	}
}
