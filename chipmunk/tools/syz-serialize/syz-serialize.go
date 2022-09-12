package main

import (
	"flag"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"io/ioutil"
)

func main() {
	var (
		flagOS   = flag.String("os", "linux", "target OS")
		flagArch = flag.String("arch", "amd64", "target arch")
	)
	flag.Parse()
	args := flag.Args()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	file := args[len(args)-1]
	entries := loadPrograms(target, file)
	unpack(entries)
}

func loadPrograms(target *prog.Target, file string) []*prog.LogEntry {
	var entries []*prog.LogEntry
	data, err := ioutil.ReadFile(file)
	if err != nil {
		log.Fatalf("failed to read log file: %v", err)
	}
	entries = append(entries, target.ParseLog(data)...)
	log.Logf(0, "parsed %v programs", len(entries))
	return entries
}

func unpack(entries []*prog.LogEntry) {
	for _, entry := range entries {
		exec := make([]byte, prog.ExecBufferSize)
		entry.P.SerializeForExec(exec)
		name := hash.String(entry.P.Serialize())
		if err := osutil.WriteFile(name, exec); err != nil {
			tool.Failf("failed to output file: %v", err)
		}
	}
}
