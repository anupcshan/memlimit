// +build linux

package main

import (
	"flag"
	"log"
	"sort"
	"syscall"
	"time"

	"github.com/prometheus/procfs"
)

func getProcStats() (map[int]procfs.ProcStat, error) {
	procs, err := procfs.AllProcs()
	if err != nil {
		return nil, err
	}

	stats := make(map[int]procfs.ProcStat)

	for _, proc := range procs {
		stat, statErr := proc.Stat()
		if statErr == nil {
			stats[proc.PID] = stat
		}
	}

	return stats, nil
}

func getPidMap(stats map[int]procfs.ProcStat) map[int][]int {
	children := make(map[int][]int, len(stats))
	for _, s := range stats {
		children[s.PPID] = append(children[s.PPID], s.PID)
	}

	return children
}

// List of process names that are allowed to be stopped.
var whitelistedProcesses = map[string]bool{
	"cc1plus": true,
	"cc1":     true,
	"as":      true,
	"ld":      true,
}

func toMB(sz uint64) uint64 {
	return sz / 1024 / 1024
}

func main() {
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)

	var flagPid int
	var flagVszLimitMb uint64
	var flagCheckInterval time.Duration
	flag.IntVar(&flagPid, "pid", 0, "PID of top-level process in process tree to track")
	flag.Uint64Var(&flagVszLimitMb, "vsz-limit-mb", 1024, "VSZ limit of non-stopped filtered processes")
	flag.DurationVar(&flagCheckInterval, "check-interval", 250*time.Millisecond, "Interval between consecutive procfs scans")
	flag.Parse()

	for true {
		stats, err := getProcStats()
		if err != nil {
			log.Println("Error listing procs", err)
			continue
		}

		if _, ok := stats[flagPid]; !ok {
			log.Printf("Process %d not found. Exiting", flagPid)
			return
		}

		if err == nil {
			pmap := getPidMap(stats)

			queue := []int{flagPid}
			var loopPid int
			m := make(map[int]struct{})
			m[flagPid] = struct{}{}
			for len(queue) > 0 {
				loopPid, queue = queue[0], queue[1:]

				for _, childPid := range pmap[loopPid] {
					if _, ok := m[childPid]; ok {
						continue
					} else {
						m[childPid] = struct{}{}
						queue = append(queue, childPid)
					}
				}
			}

			filterableVsz := uint64(0)
			filterableRss := uint64(0)

			unfilterableVsz := uint64(0)
			unfilterableRss := uint64(0)

			pids := make([]int, 0, len(m))
			for pid := range m {
				pids = append(pids, pid)
			}
			sort.Ints(pids)
			filteredRunning := 0
			filteredStopped := 0
			unfiltered := 0

			var filteredStats []procfs.ProcStat

			for _, pid := range pids {
				if _, ok := whitelistedProcesses[stats[pid].Comm]; !ok {
					unfiltered++
					unfilterableVsz += stats[pid].VirtualMemory()
					unfilterableRss += stats[pid].ResidentMemory()
					continue
				}

				if stats[pid].State == "T" {
					filteredStopped++
				} else {
					filteredRunning++
				}
				filteredStats = append(filteredStats, stats[pid])
			}

			sort.Slice(filteredStats, func(i, j int) bool {
				if filteredStats[i].Starttime != filteredStats[j].Starttime {
					return filteredStats[i].Starttime < filteredStats[j].Starttime
				}
				return filteredStats[i].PID < filteredStats[j].PID
			})

			for counter, stat := range filteredStats {
				filterableVsz += stat.VirtualMemory()
				filterableRss += stat.ResidentMemory()
				log.Println(stat.Starttime, stat.PID, stat.State, stat.Comm, toMB(stat.VirtualMemory()), toMB(stat.ResidentMemory()))
				if filterableVsz > toMB(flagVszLimitMb) && counter > 0 {
					if stat.State != "T" {
						syscall.Kill(stat.PID, syscall.SIGSTOP)
					}
				} else {
					if stat.State == "T" {
						syscall.Kill(stat.PID, syscall.SIGCONT)
					}
				}
			}

			log.Printf("Total VSZ: %dM RSS: %dM Procs: %d (Stopped: %d Running %d)", toMB(filterableVsz), toMB(filterableRss), filteredRunning+filteredStopped, filteredStopped, filteredRunning)
			log.Printf("Unfiltered VSZ: %dM RSS: %dM Procs: %d", toMB(unfilterableVsz), toMB(unfilterableRss), unfiltered)
		}
		time.Sleep(flagCheckInterval)
	}
}
