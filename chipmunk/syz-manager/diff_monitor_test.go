package main

import (
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"testing"
)

func TestDiffMonitor(t *testing.T) {
	mon := DiffMonitorCtor("/home/shankara/shared/nova-tester/")
	fmt.Printf("DiffFiles: %v", mon.diffFiles)
	err := make(chan string)
	mon.monitor(err)
	s := <-err
	log.Logf(0, "S: %s\n", s)
	close(err)
}
