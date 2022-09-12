package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
)

var (
	threshold = 10.0
)

type CCBugManager struct {
	diffMonitor     *DiffFileMonitor
	clusters        []*CrashCluster
	uiCrashClusters []*UICrashType
	file2UiCrash    map[string]*UICrash
	lock            *sync.Mutex
}

type CrashCluster struct {
	Description string
	Crashes     []*UICrash
	Vector      []float64
}

func similarity(doc1, doc2 string) float64 {
	corpus, _ := makeCorpus([]string{doc1, doc2})
	vec1 := computeVector(doc1, corpus)
	vec2 := computeVector(doc2, corpus)
	if len(vec1) != len(vec2) {
		return 0.0
	}
	diff := difference(vec1, vec2)
	return norm(diff)
}

func norm(vec1 []float64) float64 {
	if len(vec1) > 0 {
		val := 0.0
		for _, f := range vec1 {
			val += f * f
		}
		return math.Sqrt(val)
	}
	return 0.0
}

func difference(vec1 []float64, vec2 []float64) []float64 {
	if len(vec1) == len(vec2) {
		ret := make([]float64, len(vec1))
		for i := 0; i < len(vec1); i++ {
			ret[i] = vec1[i] - vec2[i]
		}
		return ret
	}
	return nil
}

func Score(doc []int, corpusSize int) []float64 {
	vec := make([]float64, corpusSize)
	hist := make(map[int]int)
	for _, id := range doc {
		if _, ok := hist[id]; !ok {
			hist[id] = 1
		} else {
			hist[id] = hist[id] + 1
		}
	}
	for id, cnt := range hist {
		vec[id] = float64(cnt) / float64(len(doc))
	}
	return vec
}

func (c *CCBugManager) genUICrash(diffFile string) *UICrash {
	//if description == "" {
	//	continue
	//}
	t := time.Now()
	logFile, progName := c.diffMonitor.GetLogFile(diffFile)
	log.Logf(0, "GETTING LOG FILE: %v", time.Now().Sub(t).Seconds())
	return &UICrash{
		0,
		time.Now(),
		true,
		logFile,
		diffFile,
		progName,
	}
}

func BugManagerCtor(workdir string) *CCBugManager {
	bmanager := new(CCBugManager)
	log.Logf(0, "CREATE MANAGER: %v", workdir)
	bmanager.lock = new(sync.Mutex)
	diffMonitor := DiffMonitorCtor(workdir)
	bmanager.diffMonitor = diffMonitor
	bmanager.uiCrashClusters = make([]*UICrashType, 0)
	//bmanager.genCrashClusters()
	bmanager.getClusters()
	return bmanager
}

func (c *CCBugManager) getCrashes() int {
	count := 0
	for _, ui := range c.uiCrashClusters {
		count += ui.Count
	}
	return count
}

func (c *CCBugManager) getCrash(id string) *UICrashType {
	for _, cluster := range c.uiCrashClusters {
		if cluster.ID == id {
			return cluster
		}
	}
	log.Fatalf("Failed to get crash: %s", id)
	return nil
}

func computeVector(doc string, corpus map[string]int) []float64 {
	retVal := make([]float64, len(corpus))
	for _, f := range strings.Fields(doc) {
		f = strings.ToLower(f)
		retVal[corpus[f]] += 1.0
	}
	return retVal
}

func (c *CCBugManager) getClusters() {
	c.lock.Lock()
	c.uiCrashClusters = make([]*UICrashType, 0)
	c.clusters = make([]*CrashCluster, 0)
	descriptions := make([]string, 0)
	diffFiles := c.diffMonitor.GetDiffFiles()
	file2uicrash := make(map[string]*UICrash)
	for _, file := range diffFiles {
		description := getCCDescription(file)
		uicrash := c.genUICrash(file)
		if uicrash == nil {
			log.Fatalf("UI CRASH IS NIL")
		}
		file2uicrash[file] = uicrash
		descriptions = append(descriptions, description)
	}
	for i := 0; i < len(descriptions); i++ {
		if len(descriptions[i]) == 0 || descriptions[i] == "" {
			continue
		}
		c.addToCluster(descriptions[i], file2uicrash[diffFiles[i]])
	}
	for i, cluster := range c.clusters {
		c.uiCrashClusters = append(c.uiCrashClusters, &UICrashType{
			Description: cluster.Description,
			LastTime:    time.Now(),
			Active:      true,
			ID:          fmt.Sprintf("diff-%d", i),
			Count:       len(cluster.Crashes),
			Crashes:     cluster.Crashes,
		})
		//log.Logf(0, "Description: %s %v %s", cluster.Description, len(cluster.Crashes), cluster.Crashes[0].Log)
	}
	c.file2UiCrash = file2uicrash
	c.lock.Unlock()
}

func (c *CCBugManager) updateClusters() {
	c.lock.Lock()
	diffFiles := c.diffMonitor.GetDiffFiles()
	for _, file := range diffFiles {
		if _, ok := c.file2UiCrash[file]; !ok {
			description := getCCDescription(file)
			if description == "" {
				continue
			}
			uicrash := c.genUICrash(file)
			if uicrash == nil {
				log.Fatalf("UI CRASH IS NIL")
			}
			c.file2UiCrash[file] = uicrash
			c.addToCluster(description, uicrash)
		}
	}
	c.uiCrashClusters = make([]*UICrashType, 0)
	for i, cluster := range c.clusters {
		c.uiCrashClusters = append(c.uiCrashClusters, &UICrashType{
			Description: cluster.Description,
			LastTime:    time.Now(),
			Active:      true,
			ID:          fmt.Sprintf("diff-%d", i),
			Count:       len(cluster.Crashes),
			Crashes:     cluster.Crashes,
		})
		//log.Logf(0, "Description: %s %v %s", cluster.Description, len(cluster.Crashes), cluster.Crashes[0].Log)
	}
	c.lock.Unlock()
}

func (c *CCBugManager) addToCluster(description string, crash *UICrash) {
	if len(c.clusters) == 0 {
		c.clusters = append(c.clusters, &CrashCluster{
			Description: description,
			Crashes:     []*UICrash{crash},
		})
		return
	}
	minScore := math.MaxFloat64
	var minCluster *CrashCluster
	for i, cluster := range c.clusters {
		if cluster.Description == description {
			c.clusters[i].Crashes = append(c.clusters[i].Crashes, crash)
			return
		} else {
			score := similarity(cluster.Description, description)
			if score < minScore {
				minScore = score
				minCluster = c.clusters[i]
			}
		}
	}
	if minScore < threshold {
		minCluster.Crashes = append(minCluster.Crashes, crash)
	} else {
		// add a new cluster
		c.clusters = append(c.clusters, &CrashCluster{
			Description: description,
			Crashes:     []*UICrash{crash},
		})
	}
}

func makeCorpus(a []string) (map[string]int, []string) {
	retVal := make(map[string]int)
	invRetVal := make([]string, 0)
	var id int
	for _, s := range a {
		for _, f := range strings.Fields(s) {
			f = strings.ToLower(f)
			if _, ok := retVal[f]; !ok {
				retVal[f] = id
				invRetVal = append(invRetVal, f)
				id++
			}
		}
	}
	return retVal, invRetVal
}

func getCCDescription(diffFile string) string {
	b, err := ioutil.ReadFile(diffFile)
	if err != nil {
		// log.Fatalf("Failed to extract crash report from diff file: %v, with error: %v", diffFile, err)
		return ""
	}
	r := bufio.NewReader(bytes.NewReader(b))
	t := time.Now()
	shouldSkipProgram := false
	text := make([]byte, 0)
	for {
		b, _, err := r.ReadLine()
		if err != nil && err.Error() == "EOF" {
			break
		}

		if bytes.Contains(bytes.ToLower(b), []byte("mount opts")) || bytes.Contains(bytes.ToLower(b), []byte("cpu")) {
			shouldSkipProgram = true
			continue
		}
		if shouldSkipProgram {
			shouldSkipProgram = false
			continue
		} else {
			log.Logf(0, "TIME TO GET DESCRIPTION: %v", time.Now().Sub(t).Seconds())
			// before returning the description, make sure that the diff file actually contains
			// some bug report content. if it doesn't skip it.
			b1, _, err := r.ReadLine()
			if err != nil && err.Error() == "EOF" {
				break
			}
			text = append(text, b...)
			text = append(text, b1...)
		}
	}
	log.Logf(0, "TEXT: %s", string(text))
	return string(text)
}
