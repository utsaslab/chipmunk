package main

import (
	"os"
	"path"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type DiffFileMonitor struct {
	workdir   string
	progDir   string
	diffFiles map[string]bool
	logMap    map[string]string
	logs      map[string]bool
	vmdirs    []string
}

func getVmDirs(workdir string) (vmdirs []string) {
	log.Logf(0, "MAKING VMDIR: %s", workdir)
	vmdirs = make([]string, 0)
	files, err := osutil.ListDir(workdir)
	if err != nil {
		log.Fatalf("Failed to miss directory: %v %v\n", err, workdir)
	}
	// r, _ := regexp.Compile("vm-[0-9]+")
	r, _ := regexp.Compile("vmshare-[0-9]+")
	for _, f := range files {
		if r.Match([]byte(f)) {
			vmdirs = append(vmdirs, f)
		}
	}
	return
}

func DiffMonitorCtor(workdir string) (mon *DiffFileMonitor) {
	mon = new(DiffFileMonitor)
	mon.workdir = workdir
	// mon.vmdirs = getVmDirs(workdir)
	// log.Logf(0, "VMDIRS: %v\n", mon.vmdirs)
	mon.diffFiles = make(map[string]bool)
	mon.logMap = make(map[string]string)
	mon.logs = make(map[string]bool)
	mon.progDir = path.Join(workdir, "/crashConsistencyProgs")
	files := mon.GetDiffFiles()
	for _, f := range files {
		mon.diffFiles[f] = true
	}
	return
}

func timespecToTime(ts syscall.Timespec) time.Time {
	return time.Unix(int64(ts.Sec), int64(ts.Nsec))
}

func (d *DiffFileMonitor) GetLogFile(file string) (logfile string, progName string) {
	//log.Logf(0, "DIFF FILE: %v", file)
	s := strings.Split(file, "diff-")
	if len(s) > 1 {
		s1 := strings.Split(s[1], "_")
		if len(s1) > 0 {
			progName = s1[0]
		} else {
			progName = s[1]
		}
		//log.Logf(0, "FILE: %v", file)
		t := strings.Split(file, "/")
		vmDir := ""
		//r, _ := regexp.Compile("vm-[0-9]+")
		for _, f := range t {
			if strings.Contains(f, "vmshare-") {
				vmDir = f
				break
			}
		}
		logDir := path.Join(d.workdir, vmDir, "logs", "workloads")
		log.Logf(0, "%v", logDir)
		log.Logf(0, "%v", progName)

		d.logMap = make(map[string]string)

		if file, ok := d.logMap[progName]; ok {
			log.Logf(0, "CACHE")
			logfile = file
		} else {
			files, err := osutil.ListDir(logDir)
			if err != nil {
				//log.Logf(0, "FAILED TO STAT LOG FILE: %v", err)
				// progName = path.Join(d.progDir, progName)
				progName = path.Join(d.workdir, vmDir, "/crashConsistencyProgs/", progName)
				log.Logf(0, "%v", progName)
				return
			}
			for _, f := range files {
				fullPath := path.Join(logDir, f)
				if _, ok := d.logMap[fullPath]; ok {
					continue
				}
				spl := strings.Split(f, "-")
				if len(spl) > 1 {
					prog := strings.Split(spl[1], "_")
					if len(prog) > 1 {
						d.logMap[prog[0]] = fullPath
						d.logs[f] = true
					} else {
						prog = strings.Split(spl[1], ".")
						if len(prog) > 1 {
							d.logMap[prog[0]] = fullPath
							d.logs[f] = true
						}
					}
				}
			}
			logfile = d.logMap[progName]
		}
		log.Logf(0, "progname: %v", progName)
		progName = path.Join(d.workdir, vmDir, "/crashConsistencyProgs/", progName)
		log.Logf(0, "progname path: %v", progName)
		return
	}
	return
}

func (d *DiffFileMonitor) GetDiffFiles() []string {
	files := make([]string, 0)
	d.vmdirs = getVmDirs(d.workdir)
	log.Logf(0, "VMDIRS: %v", d.vmdirs)
	for _, dir := range d.vmdirs {
		diffDir := path.Join(d.workdir, dir, "logs", "diffs")
		diffs, err := osutil.ListDir(diffDir)
		if err != nil {
			// log.Fatalf("Failed to read diff dir: %v", err)
			continue
		}
		for _, diff := range diffs {
			fullPath := path.Join(diffDir, diff)
			finfo, err := os.Stat(fullPath)
			if err != nil {
				continue
			}
			stat_t := finfo.Sys().(*syscall.Stat_t)
			// if the file has been created too recently then the tester may delete it
			if !timespecToTime(stat_t.Ctim).Add(1 * time.Second).Before(time.Now()) {
				continue
			}
			files = append(files, fullPath)
		}
	}
	log.Logf(0, "FILES: %v", files)
	return files
}

func (d *DiffFileMonitor) monitor(err chan string) {
	go func() {
		ticker := time.NewTicker(10 * time.Millisecond)
		for {
			select {
			case <-ticker.C:
				files := d.GetDiffFiles()
				for _, f := range files {
					_, ok := d.diffFiles[f]
					if !ok {
						d.diffFiles[f] = true
						//log.Logf(0, "New file: %s\n", f)
						err <- f
					}
				}
			}
		}
	}()
}
