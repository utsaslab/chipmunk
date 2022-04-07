// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	. "github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func buildExecutor(t *testing.T, target *prog.Target) string {
	src := filepath.FromSlash("../../executor/executor.cc")
	bin, err := csource.BuildFile(target, src)
	if err != nil {
		t.Fatal(err)
	}
	return bin
}

func initTest(t *testing.T) (*prog.Target, rand.Source, int, bool, bool, targets.Timeouts) {
	t.Parallel()
	iters := 100
	if testing.Short() {
		iters = 10
	}
	seed := time.Now().UnixNano()
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := ipcconfig.Default(target)
	if err != nil {
		t.Fatal(err)
	}
	return target, rs, iters, cfg.UseShmem, cfg.UseForkServer, cfg.Timeouts
}

// TestExecutor runs all internal executor unit tests.
// We do it here because we already build executor binary here.
func TestExecutor(t *testing.T) {
	t.Parallel()
	for _, sysTarget := range targets.List[runtime.GOOS] {
		sysTarget := targets.Get(runtime.GOOS, sysTarget.Arch)
		t.Run(sysTarget.Arch, func(t *testing.T) {
			if sysTarget.BrokenCompiler != "" {
				t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
			}
			t.Parallel()
			target, err := prog.GetTarget(runtime.GOOS, sysTarget.Arch)
			if err != nil {
				t.Fatal(err)
			}
			bin := buildExecutor(t, target)
			defer os.Remove(bin)
			// qemu-user may allow us to run some cross-arch binaries.
			if _, err := osutil.RunCmd(time.Minute, "", bin, "test"); err != nil {
				if sysTarget.Arch == runtime.GOARCH || sysTarget.VMArch == runtime.GOARCH {
					t.Fatal(err)
				}
				t.Skipf("skipping, cross-arch binary failed: %v", err)
			}
		})
	}
}

func TestExecute(t *testing.T) {
	target, _, _, useShmem, useForkServer, timeouts := initTest(t)

	bin := buildExecutor(t, target)
	defer os.Remove(bin)

	flags := []ExecFlags{0, FlagThreaded, FlagThreaded | FlagCollide}
	for _, flag := range flags {
		t.Logf("testing flags 0x%x\n", flag)
		cfg := &Config{
			Executor:      bin,
			UseShmem:      useShmem,
			UseForkServer: useForkServer,
			Timeouts:      timeouts,
		}
		env, err := MakeEnv(cfg, 0)
		if err != nil {
			t.Fatalf("failed to create env: %v", err)
		}
		defer env.Close()

		for i := 0; i < 10; i++ {
			p := target.DataMmapProg()
			opts := &ExecOpts{
				Flags: flag,
			}
			output, info, hanged, err := env.Exec(opts, p, "test")
			if err != nil {
				t.Fatalf("failed to run executor: %v", err)
			}
			if hanged {
				t.Fatalf("program hanged:\n%s", output)
			}
			if len(info.Calls) == 0 {
				t.Fatalf("no calls executed:\n%s", output)
			}
			if info.Calls[0].Errno != 0 {
				t.Fatalf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
			}
			if len(output) != 0 {
				t.Fatalf("output on empty program")
			}
		}
	}
}

func TestParallel(t *testing.T) {
	target, _, _, useShmem, useForkServer, timeouts := initTest(t)
	bin := buildExecutor(t, target)
	defer os.Remove(bin)
	cfg := &Config{
		Executor:      bin,
		UseShmem:      useShmem,
		UseForkServer: useForkServer,
		Timeouts:      timeouts,
	}
	const P = 10
	errs := make(chan error, P)
	for p := 0; p < P; p++ {
		p := p
		go func() {
			env, err := MakeEnv(cfg, p)
			if err != nil {
				errs <- fmt.Errorf("failed to create env: %v", err)
				return
			}
			defer func() {
				env.Close()
				errs <- err
			}()
			p := target.DataMmapProg()
			opts := &ExecOpts{}
			output, info, hanged, err := env.Exec(opts, p, "test")
			if err != nil {
				err = fmt.Errorf("failed to run executor: %v", err)
				return
			}
			if hanged {
				err = fmt.Errorf("program hanged:\n%s", output)
				return
			}
			if len(info.Calls) == 0 {
				err = fmt.Errorf("no calls executed:\n%s", output)
				return
			}
			if info.Calls[0].Errno != 0 {
				err = fmt.Errorf("simple call failed: %v\n%s", info.Calls[0].Errno, output)
				return
			}
			if len(output) != 0 {
				err = fmt.Errorf("output on empty program")
				return
			}
		}()
	}
	for p := 0; p < P; p++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}

func TestEnv_Exec(t *testing.T) {
	type fields struct {
		in           []byte
		out          []byte
		outMount     []byte
		cmd          *command
		inFile       *os.File
		outFile      *os.File
		outFileMount *os.File
		bin          []string
		linkedBin    string
		pid          int
		config       *Config
		StatExecs    uint64
		StatRestarts uint64
	}
	type args struct {
		opts *ExecOpts
		p    *prog.Prog
		name string
	}
	tests := []struct {
		name       string
		fields     fields
		args       args
		wantOutput []byte
		wantInfo   *ProgInfo
		wantHanged bool
		wantErr    bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := &Env{
				in:           tt.fields.in,
				out:          tt.fields.out,
				outMount:     tt.fields.outMount,
				cmd:          tt.fields.cmd,
				inFile:       tt.fields.inFile,
				outFile:      tt.fields.outFile,
				outFileMount: tt.fields.outFileMount,
				bin:          tt.fields.bin,
				linkedBin:    tt.fields.linkedBin,
				pid:          tt.fields.pid,
				config:       tt.fields.config,
				StatExecs:    tt.fields.StatExecs,
				StatRestarts: tt.fields.StatRestarts,
			}
			gotOutput, gotInfo, gotHanged, err := env.Exec(tt.args.opts, tt.args.p, tt.args.name)
			if (err != nil) != tt.wantErr {
				t.Errorf("Env.Exec() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotOutput, tt.wantOutput) {
				t.Errorf("Env.Exec() gotOutput = %v, want %v", gotOutput, tt.wantOutput)
			}
			if !reflect.DeepEqual(gotInfo, tt.wantInfo) {
				t.Errorf("Env.Exec() gotInfo = %v, want %v", gotInfo, tt.wantInfo)
			}
			if gotHanged != tt.wantHanged {
				t.Errorf("Env.Exec() gotHanged = %v, want %v", gotHanged, tt.wantHanged)
			}
		})
	}
}
