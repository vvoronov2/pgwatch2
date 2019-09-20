package main

import (
	"bufio"
	"regexp"

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
		}
	}
	return latest, maxDate
}

func getFileWithNextModTimestamp(files []string, file string, fileMod time.Time) (string, time.Time) {
	var nextFile string
	var nextMod time.Time

	for _, f := range files {
		if f == file {
			continue
		}
		fi, err := os.Stat(f)
		if err != nil {
			log.Errorf("Failed to stat() file %s: %s", f, err)
			continue
		}
		if nextMod.IsZero() || fi.ModTime().Before(nextMod) {
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

var PG_SEVERITIES = [...]string{"DEBUG5", "DEBUG4", "DEBUG3", "DEBUG2", "DEBUG1", "INFO", "NOTICE", "WARNING", "ERROR", "LOG", "FATAL", "PANIC"}

func SeverityIsGreaterOrEqualTo(severity, threshold string) bool {
	thresholdPassed := false
	for i, s := range PG_SEVERITIES {
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

// globpath /var/lib/postgresql/*/main/pg_log
func logparseLoop() {
	var latest string
	var latestModTime time.Time
	var firstFile bool = true

	var csvlog string = `^(?P<log_time>.*?),"?(?P<user_name>.*?)"?,"?(?P<database_name>.*?)"?,(?P<process_id>\d+),"(?P<connection_from>.*?)",(?P<session_id>.*?),(?P<session_line_num>\d+),"(?P<command_tag>.*?)",(?P<session_start_time>.*?),(?P<virtual_transaction_id>.*?),(?P<transaction_id>.*?),(?P<error_severity>\w+),`
	csvlogRegex := regexp.MustCompile(csvlog)

	//go tailer()

	logFile, err := os.Open("/tmp/postgresql-Wed.csv")
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	r := bufio.NewReader(logFile)
	i:=0
	for {
		line, err := r.ReadString('\n')
		if err != nil && err != io.EOF {
			panic(err)
		}
		matches := csvlogRegex.FindStringSubmatch(line)
		log.Error(matches)

		result := RegexMatchesToMap(csvlogRegex, matches)
		// log.Fatal(result)
		if severity, ok := result["error_severity"] ; ok && SeverityIsGreaterOrEqualTo(severity, PG_SEVERITIES) {
			log.Warning(serv)
		}


		i++
		if i > 10 {
			panic("ok")
		}

		if err == io.EOF {
			time.Sleep(time.Second)
		}
	}

	for {
		log.Info("Considering log files determined by glob pattern:", opts.Globpath)
		matches, err := filepath.Glob(opts.Globpath)
		if err != nil {
			log.Warning("No logfiles found to parse. Sleeping 5s...")
			time.Sleep(5 * time.Second)
			continue
		}

		// set up inotify TODO
		// kuidas saab hakkama weekly recyclega ?
		if firstFile {
			log.Debugf("Found %v logfiles to parse", len(matches))
			if len(matches) > 1 {
				// find latest timestamp
				latest, latestModTime = getFileWithLatestTimestamp(matches)
				if latest == "" {
					log.Warning("Could not determine the latest logfile. Sleeping 10s...")
					time.Sleep(10 * time.Second)
					continue
				}

				log.Debugf("Latest logfile: %s (%v)", latest, latestModTime)
				logFilesToTail <- latest
				firstFile = false
			}

		} else {
			file, mod := getFileWithNextModTimestamp(matches, latest, latestModTime)
			if file != "" {
				latest = file
				latestModTime = mod
				log.Info("Switching to new logfile", file, mod)
				logFilesToTail <- file
			} else {
				log.Debug("No newer logfiles found...")
			}
		}

		//logFilesToTailLock.Lock()

		time.Sleep(500 * time.Second)

		//os.Exit(0)
	}
}

func RegexMatchesToMap(csvlogRegex *regexp.Regexp, matches []string) map[string]string {
	result := make(map[string]string)
	for i, name := range csvlogRegex.SubexpNames() {
		if i != 0 && name != "" {
			result[name] = matches[i]
		}
	}
	return result
}
