package main

import (
	"testing"
)

func TestCCBugManager(t *testing.T) {
	m := BugManagerCtor("/home/shankara/shared/nova-tester")
	if m != nil {
		t.Fatalf("Failed to create manager")
	}
}
