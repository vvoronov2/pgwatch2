package main

import (
	"bufio"
	"regexp"
	"strings"

	//	"encoding/csv"
	"github.com/hpcloud/tail"
	"io"

	//	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

var logFilesToTail = make(chan string, 10000) // main loop adds, worker fetches
var logFilesToTailLock = sync.RWMutex{}
var lastParsedLineTimestamp time.Time
var PG_SEVERITIES = [...]string{"DEBUG5", "DEBUG4", "DEBUG3", "DEBUG2", "DEBUG1", "INFO", "NOTICE", "WARNING", "ERROR", "LOG", "FATAL", "PANIC"}
var PG_SEVERITIES_MAP = map[string]int{"DEBUG5": 1, "DEBUG4": 2, "DEBUG3": 3, "DEBUG2": 4, "DEBUG1": 5, "INFO": 6, "NOTICE": 7, "WARNING": 8, "ERROR": 9, "LOG": 10, "FATAL": 11, "PANIC": 12}

const DEFAULT_LOG_SEVERITY = "WARNING"
const CSVLOG_DEFAULT_REGEX  = `^^(?P<log_time>.*?),"?(?P<user_name>.*?)"?,"?(?P<database_name>.*?)"?,(?P<process_id>\d+),"?(?P<connection_from>.*?)"?,(?P<session_id>.*?),(?P<session_line_num>\d+),"?(?P<command_tag>.*?)"?,(?P<session_start_time>.*?),(?P<virtual_transaction_id>.*?),(?P<transaction_id>.*?),(?P<error_severity>\w+),`

// https://www.reddit.com/r/golang/comments/60ck9o/why_is_it_hard_to_mimic_tail_f_behavior/
//http://satran.in/2017/11/15/Implementing_tails_follow_in_go.html
// TODO ignore all entries older than now() so that no state is required

func getFileWithLatestTimestamp(files []string) (string, time.Time) {
	var maxDate time.Time
	var latest string

	for _, f := range files {
		fi, err := os.Stat(f)
		if err != nil {
			log.Errorf("Failed to stat() file %s: %s", f, err)
			continue
		}
		if fi.ModTime().After(maxDate) {
			latest = f
			maxDate = fi.ModTime()
		}
	}
	return latest, maxDate
}

func getFileWithNextModTimestamp(dbUniqueName, logsGlobPath, currentFile string) (string, time.Time) {
	var nextFile string
	var nextMod time.Time

	files, err := filepath.Glob(logsGlobPath)
	if err != nil {
		log.Error("[%s] Error globbing \"%s\"...", dbUniqueName, logsGlobPath)
		return "", time.Now()
	}

	fiCurrent, err := os.Stat(currentFile)
	if err != nil {
		log.Errorf("Failed to stat() currentFile %s: %s", currentFile, err)
		return "", time.Now()
	}
	//log.Debugf("Stat().ModTime() for %s: %v", currentFile, fiCurrent.ModTime())

	for _, f := range files {
		if f == currentFile {
			continue
		}
		fi, err := os.Stat(f)
		if err != nil {
			log.Errorf("Failed to stat() currentFile %s: %s", f, err)
			continue
		}
		//log.Debugf("Stat().ModTime() for %s: %v", f, fi.ModTime())
		if (nextMod.IsZero() || fi.ModTime().Before(nextMod)) && fi.ModTime().After(fiCurrent.ModTime()) {
			nextMod = fi.ModTime()
			nextFile = f
		}
	}
	return nextFile, nextMod
}

func tailer() {
	var curFile string
	var lines int
	var firstFile bool = true

	for {
		log.Debug("Waiting for files to tail...")
		if len(logFilesToTail) > 0 {
			curFile = <-logFilesToTail
		} else {
			if firstFile {
				time.Sleep(1 * time.Second)
				continue
			}
		}
		if curFile == "" {
			log.Fatal("curFile empty")
		}
		log.Debugf("Tailing %s", curFile)
		t, err := tail.TailFile(curFile, tail.Config{Follow: true, ReOpen: true, Logger: tail.DiscardingLogger}) // TODO Location os.Stat len

		if err != nil {
			log.Errorf("Could not tail %s:", err)
			if len(logFilesToTail) == 0 {
				log.Debug("Sleeping 10s before retrying")
				time.Sleep(5 * time.Second)
				continue
			} else {
				continue // take next curFile
			}
		}
		lines = 0
		log.Errorf("t: %+v", t)

		for line := range t.Lines {
			if line.Err != nil {
				log.Error("line.Err", line.Err)
				time.Sleep(1 * time.Second)
				break
			}
			lines++
			//log.Error("line", line.Text)
		}
		log.Error("lines", lines)
	}
}

type Client struct { // Our example struct, you can use "-" to ignore a field
	log_time               string `csv:"log_time"`
	user_name              string `csv:"user_name"`
	database_name          string `csv:"database_name"`
	process_id             string `csv:"process_id"`
	connection_from        string `csv:"connection_from"`
	session_id             string `csv:"session_id"`
	session_line_num       string `csv:"session_line_num"`
	command_tag            string `csv:"command_tag"`
	session_start_time     string `csv:"session_start_time"`
	virtual_transaction_id string `csv:"virtual_transaction_id"`
	transaction_id         string `csv:"transaction_id"`
	error_severity         string `csv:"error_severity"`
	sql_state_code         string `csv:"sql_state_code"`
	message                string `csv:"message"`
	detail                 string `csv:"detail"`
	hint                   string `csv:"hint"`
	internal_query         string `csv:"internal_query"`
	internal_query_pos     string `csv:"internal_query_pos"`
	context                string `csv:"context"`
	query                  string `csv:"query"`
	query_pos              string `csv:"query_pos"`
	location               string `csv:"location"`
	application_name       string `csv:"application_name"`
}


func SeverityIsGreaterOrEqualTo(severity, threshold string) bool {
	thresholdPassed := false
	for _, s := range PG_SEVERITIES {
		if s == threshold {
			thresholdPassed = true
			break
		} else if s == severity {
			return false
		}
	}
	if thresholdPassed {
		return true
	} else {
		log.Fatal("Should not happen")
	}
	return false
}

func eventCountsToMetricStoreMessages(eventCounts map[string]int64, logsMinSeverity string, mdb MonitoredDatabase) []MetricStoreMessage {
	thresholdPassed := false
	allSeverityCounts := make(map[string]interface{})

	for _, s := range PG_SEVERITIES {
		if s == logsMinSeverity {
			thresholdPassed = true
		}
		if !thresholdPassed {
			continue
		}
		parsedCount, ok := eventCounts[s]
		if ok {
			allSeverityCounts[strings.ToLower(s)] = parsedCount
		} else {
			allSeverityCounts[strings.ToLower(s)] = 0
		}
	}
	allSeverityCounts["epoch_ns"] = time.Now().UnixNano()
	var data []map[string]interface{}
	data = append(data, allSeverityCounts)
	return []MetricStoreMessage{{DBUniqueName: mdb.DBUniqueName, DBType: mdb.DBType,
			MetricName: POSTGRESQL_LOG_PARSING_METRIC_NAME, Data: data, CustomTags: mdb.CustomTags}}
}



// TODO control_ch
func logparseLoop(dbUniqueName, metricName string, config_map map[string]float64, control_ch <-chan ControlMessage, store_ch chan<- []MetricStoreMessage) {

	var latest, previous string
	var latestHandle *os.File
	var reader *bufio.Reader
	var linesRead = 0							// to skip over already parsed lines on Postgres server restart for example
    var logsMatchRegex, logsGlobPath, logsMinSeverity string
	var lastSendTime time.Time               // to storage channel
	var lastConfigRefreshTime time.Time      // MonitoredDatabase info
	var eventCounts = make(map[string]int64) // [WARNING: 34, ERROR: 10, ...], re-created on storage send
	var mdb MonitoredDatabase
	var hostConfig HostConfigAttrs
	var err error
	var firstRun = true

	for {	// re-try loop. re-start in case of FS errors or just to refresh host config

		if lastConfigRefreshTime.IsZero() ||  lastConfigRefreshTime.Add(time.Second*time.Duration(opts.ServersRefreshLoopSeconds)).Before(time.Now()) {
			mdb, err = GetMonitoredDatabaseByUniqueName(dbUniqueName)
			if err != nil {
				log.Error(err)
				time.Sleep(60 * time.Second)
				continue
			}
			hostConfig = mdb.HostConfig	// TODO after ServersRefreshLoopSeconds
			log.Debugf("[%s] hostConfig: %+v", dbUniqueName, hostConfig)
		}

		logsMatchRegex = hostConfig.LogsMatchRegex
		if logsMatchRegex == "" {
			log.Infof("[%s] Setting default logparse regex", dbUniqueName)
			logsMatchRegex = CSVLOG_DEFAULT_REGEX
		}
		logsGlobPath = hostConfig.LogsGlobPath
		if logsGlobPath == "" {
			logsGlobPath = tryDetermineLogFolder(dbUniqueName)
			if logsGlobPath == "" {
				log.Warningf("[%s] Could not determine Postgres logs parsing folder. Configured logs_glob_path = %s", dbUniqueName, logsGlobPath)
				time.Sleep(60 * time.Second)
				continue
			}
		}

		logsMinSeverity = hostConfig.LogsMinSeverity
		if logsMinSeverity == "" {
			logsMinSeverity = DEFAULT_LOG_SEVERITY
			log.Infof("[%s] Using default min. log severity (%s) as host_config.logs_min_severity not specified", dbUniqueName, DEFAULT_LOG_SEVERITY)
		} else {
			_, ok := PG_SEVERITIES_MAP[logsMinSeverity]
			if !ok {
				logsMinSeverity = DEFAULT_LOG_SEVERITY
				log.Infof("[%s] Invalid logs_min_severity (%s) specified, using default min. log severity: %s", dbUniqueName, hostConfig.LogsMinSeverity, DEFAULT_LOG_SEVERITY)
			} else {
				log.Debugf("[%s] Configured logs min. error_severity: %s", dbUniqueName, logsMinSeverity)
			}
		}

		csvlogRegex := regexp.MustCompile(logsMatchRegex)	// TODO err handling

		log.Debugf("[%s] Considering log files determined by glob pattern: %s", dbUniqueName, logsGlobPath)

		// set up inotify TODO
		// kuidas saab hakkama weekly recyclega ?
		if latest == "" || firstRun {

			globMatches, err := filepath.Glob(logsGlobPath)
			if err != nil || len(globMatches) == 0 {
				log.Infof("[%s] No logfiles found to parse. Sleeping 60s...", dbUniqueName)
				time.Sleep(60 * time.Second)
				continue
			}

			log.Debugf("[%s] Found %v logfiles from glob pattern, picking the latest", dbUniqueName, len(globMatches))
			if len(globMatches) > 1 {
				// find latest timestamp
				latest, _ = getFileWithLatestTimestamp(globMatches)
				if latest == "" {
					log.Warningf("[%s] Could not determine the latest logfile. Sleeping 60s...")
					time.Sleep(60 * time.Second)
					continue
				}

				//logFilesToTail <- latest
			} else if len(globMatches) == 1  {
				latest = globMatches[0]
			}
			log.Infof("[%s] Starting to parse logfile: %s ", dbUniqueName, latest)
		}

		if latestHandle == nil {
			latestHandle, err = os.Open(latest)
			if err != nil {
				log.Warningf("[%s] Failed to open logfile %s: %s. Sleeping 60s...", dbUniqueName, latest, err)
				time.Sleep(60 * time.Second)
				continue
			}
			reader = bufio.NewReader(latestHandle)
			if previous == latest && linesRead > 0 {	// handle postmaster restarts
				i := 1
				for i <= linesRead {
					_, err = reader.ReadString('\n')
					if err == io.EOF && i < linesRead {
						log.Warningf("[%s] Failed to open logfile %s: %s. Sleeping 60s...", dbUniqueName, latest, err)
						linesRead = 0
						break
					} else if err != nil {
						log.Warningf("[%s] Failed to skip %d logfile lines for %s, there might be duplicates reported. Error: %s", dbUniqueName, linesRead, latest, err)
						time.Sleep(60 * time.Second)
						linesRead = i
						break
					}
					i++
				}
				log.Debug("[%s] Skipped %d already processed lines from %s", dbUniqueName, linesRead, latest)
			} else if firstRun {	// seek to end
				latestHandle.Seek(0, 2)
				firstRun = false
			}
		}

		var eofSleepMillis = 0
		readLoopStart := time.Now()

		for  {
			if readLoopStart.Add(time.Second * time.Duration(opts.ServersRefreshLoopSeconds)).Before(time.Now()) {
				break	// refresh config
			}
			line, err := reader.ReadString('\n')
			if err != nil && err != io.EOF {
				log.Warningf("[%s] Failed to read logfile %s: %s. Sleeping 60s...", dbUniqueName, latest, err)
				err = latestHandle.Close()
				if err != nil {
					log.Warningf("[%s] Failed to close logfile %s properly: %s", dbUniqueName, latest, err)
				}
				latestHandle = nil
				time.Sleep(60 * time.Second)
				break
			}

			if err == io.EOF {
				//log.Debugf("[%s] EOF reached for logfile %s", dbUniqueName, latest)
				if eofSleepMillis < 5000 {
					eofSleepMillis += 1000	// progressively sleep more if nothing going on
				}
				time.Sleep(time.Millisecond * time.Duration(eofSleepMillis))

				// check for newly opened logfiles
				file, _ := getFileWithNextModTimestamp(dbUniqueName, logsGlobPath, latest)
				if file != "" {
					previous = latest
					latest = file
					err = latestHandle.Close()
					latestHandle = nil
					if err != nil {
						log.Warningf("[%s] Failed to close logfile %s properly: %s", dbUniqueName, latest, err)
					}
					log.Errorf("[%s] Switching to new logfile: %s", dbUniqueName, file)
					linesRead = 0
					break
				} else {
					log.Debugf("[%s] No newer logfiles found. Sleeping %v ms...", dbUniqueName, eofSleepMillis)
				}
				//continue
			} else {
				eofSleepMillis = 0
				linesRead++
			}

			if err == nil && line != "" {

				matches := csvlogRegex.FindStringSubmatch(line)
				if len(matches) == 0 {
					log.Warningf("[%s] No logline regex match for line:", dbUniqueName) // normal case actually, for multiline
					log.Warningf(line)
					continue
				}

				result := RegexMatchesToMap(csvlogRegex, matches)
				log.Debug("RegexMatchesToMap", result)
				severity, ok := result["error_severity"]
				_, valid_severity := PG_SEVERITIES_MAP[severity]
				if !ok || !valid_severity {
					log.Warningf("Invalid logline error_severity (%s), ignoring line: %s", severity, line) // normal case actually, for multiline
					continue
				}
				if SeverityIsGreaterOrEqualTo(severity, logsMinSeverity) {
					//log.Debug("found matching log line")
					//log.Debug(line)
					eventCounts[severity]++
				}
			}

			metricInterval, _ := config_map[POSTGRESQL_LOG_PARSING_METRIC_NAME] // TODO what if changes?
			if lastSendTime.IsZero() || lastSendTime.Before(time.Now().Add(-1 * time.Second * time.Duration(metricInterval))) {
				log.Debugf("[%s] Sending log event counts for last interval to storage channel. Eventcounts: %+v", dbUniqueName, eventCounts)
				metricStoreMessages := eventCountsToMetricStoreMessages(eventCounts, logsMinSeverity, mdb)
				store_ch <- metricStoreMessages
				eventCounts = make(map[string]int64)
				lastSendTime = time.Now()
			}

		}	// file read loop
		//panic("ok 20")
	}	// config loop

}

func tryDetermineLogFolder(dbUnique string) string {
	return ""
}

func RegexMatchesToMap(csvlogRegex *regexp.Regexp, matches []string) map[string]string {
	result := make(map[string]string)
	if matches == nil || len(matches) == 0 || csvlogRegex == nil {
		return result
	}
	for i, name := range csvlogRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}
	return result
}
