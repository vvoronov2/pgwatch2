package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Exporter struct {
	URI                               string
	up                                prometheus.Gauge
	totalScrapes, totalScrapeFailures prometheus.Counter
	serverMetrics                     map[int]*prometheus.Desc
}

func NewExporter() (*Exporter, error) {
	return &Exporter{
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: "pgwatch2",
			Name:      "up",
			Help:      "Was the last scrape of haproxy successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "pgwatch2",
			Name:      "exporter_total_scrapes",
			Help:      "Total scrape attempts.",
		}),
		totalScrapeFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: "pgwatch2",
			Name:      "exporter_total_scrape_failures",
			Help:      "Number of errors while executing metric queries",
		}),
	}, nil
}

// Describe describes all the metrics ever exported by the HAProxy exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// ch <- e.up.Desc()
	// ch <- e.totalScrapes.Desc()
	// ch <- e.totalScrapeFailures.Desc()
}

// Collect fetches the stats from configured HAProxy location and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {

	e.totalScrapes.Add(1)
	e.totalScrapeFailures.Add(1)

	ch <- prometheus.MustNewConstMetric(e.up.Desc(), prometheus.GaugeValue, 1)
	ch <- e.totalScrapes
	ch <- e.totalScrapeFailures
	m := prometheus.MustNewConstMetric(prometheus.NewDesc("pgwatch2_sadasd", "sadasd", nil, nil), prometheus.GaugeValue, 100)
	ch <- prometheus.NewMetricWithTimestamp(time.Now(), m)

	monitoredDatabases := getMonitoredDatabasesSnapshot()
	if len(monitoredDatabases) == 0 {
		log.Warning("No dbs configured for monitoring. Check config")
		return
	}
	for name, md := range monitoredDatabases {
		log.Warning("processing host:", name, ", metrics:", md.Metrics)
		for metric, interval := range md.Metrics {
			if interval > 0 {
				log.Warning("scraping", metric, ":", interval)
				metricStoreMessages, err := FetchMetrics( // TODO pooling
					MetricFetchMessage{DBUniqueName: name, MetricName: metric, DBType: md.DBType},
					nil,
					nil,
					CONTEXT_PROMETHEUS_SCRAPE)
				if err != nil {
					log.Errorf("failed to fetch [%s:%s]: %v", name, metric, err)
					continue
				}
				log.Warning("metricStoreMessages", metricStoreMessages)
				promMetrics := MetricStoreMessageToPromMetrics(metricStoreMessages[0])
				for _, pm := range promMetrics { // collect & send later in batch? capMetricChan = 1000 limit in prometheus code
					ch <- pm
				}
			}
		}
	}
}

func getMonitoredDatabasesSnapshot() map[string]MonitoredDatabase {
	mdSnap := make(map[string]MonitoredDatabase)

	if monitored_db_cache != nil {
		monitored_db_cache_lock.RLock()
		defer monitored_db_cache_lock.RUnlock()

		for _, row := range monitored_db_cache {
			mdSnap[row.DBUniqueName] = row
		}
	}

	return mdSnap
}

func MetricStoreMessageToPromMetrics(msg MetricStoreMessage) []prometheus.Metric {
	promMetrics := make([]prometheus.Metric, 0)

	var epoch_time time.Time
	var epoch_ns int64

	if len(msg.Data) == 0 {
		return promMetrics
	}

	epoch_ns, ok := (msg.Data[0][EPOCH_COLUMN_NAME]).(int64)
	if !ok {
		if msg.MetricName != "pgbouncer_stats" {
			log.Warning("No timestamp_ns found, (gatherer) server time will be used. measurement:", msg.MetricName)
		}
		epoch_time = time.Now()
	} else {
		epoch_time = time.Unix(0, epoch_ns)
	}

	for _, dr := range msg.Data {
		labels := make(map[string]string)
		fields := make(map[string]float64)
		labels["dbname"] = msg.DBUniqueName

		for k, v := range dr {
			if v == nil || v == "" || k == EPOCH_COLUMN_NAME {
				continue // not storing NULLs. epoch checked/assigned once
			}

			if strings.HasPrefix(k, "tag_") {
				tag := k[4:]
				labels[tag] = fmt.Sprintf("%v", v)
			} else {
				dataType := reflect.TypeOf(v).String()
				if dataType == "float64" || dataType == "float32" || dataType == "int64" || dataType == "int32" || dataType == "int" || dataType == "decimal.Decimal" {
					f, err := strconv.ParseFloat(fmt.Sprintf("%v", v), 64)
					if err != nil {
						log.Warningf("Skipping scraping column %s of [%s:%s]: %v", k, msg.DBUniqueName, msg.MetricName, err)
					}
					fields[k] = f
				} else if dataType == "bool" {
					if v.(bool) {
						fields[k] = 1
					} else {
						fields[k] = 0
					}
				} else {
					log.Warningf("Skipping scraping column %s of [%s:%s], unsupported datatype: %s", k, msg.DBUniqueName, msg.MetricName, dataType)
				}
			}
		}
		if msg.CustomTags != nil {
			for k, v := range msg.CustomTags {
				labels[k] = fmt.Sprintf("%v", v)
			}
		}

		label_keys := make([]string, 0)
		label_values := make([]string, 0)
		for k, v := range labels {
			label_keys = append(label_keys, k)
			label_values = append(label_values, v)
		}
		// for all fields a separate metric named: pgwatch2_metricname_columnname
		for field, value := range fields {
			desc := prometheus.NewDesc(fmt.Sprintf("%s_%s_%s", "pgwatch2", msg.MetricName, field),
				msg.MetricName, label_keys, nil)
			m := prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, value, label_values...) // TODO gauge vs counter
			promMetrics = append(promMetrics, prometheus.NewMetricWithTimestamp(epoch_time, m))

		}
	}
	return promMetrics
}

func StartPrometheusExporter(port int64) {
	promExporter, err := NewExporter()
	if err != nil {
		log.Fatal(err)
	}

	prometheus.MustRegister(promExporter)

	var promServer = &http.Server{Addr: fmt.Sprintf(":%d", opts.PrometheusPort), Handler: promhttp.Handler()}

	go func() {
		for { // ListenAndServe call should not normally return, but looping just in case
			log.Info("starting Prometheus exporter on port %d ...", opts.PrometheusPort)
			log.Error("Prometheus listener failure:", promServer.ListenAndServe())
			time.Sleep(time.Second * 1)
		}
	}()
}
