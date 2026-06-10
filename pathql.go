package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/mevdschee/pathsqlx"
)

var config Config

// Config contains all configuration
type Config struct {
	Driver  string
	DSN     string
	Listen  string
	Verbose bool
}

// Metrics holds request metrics
type Metrics struct {
	status200         uint64
	status400         uint64
	status500         uint64
	statusOther       uint64
	latencyLt1ms      uint64
	latencyLt5ms      uint64
	latencyLt10ms     uint64
	latencyLt50ms     uint64
	latencyLt100ms    uint64
	latencyLt500ms    uint64
	latencyLt1000ms   uint64
	latencyLt5000ms   uint64
	latencyLt10000ms  uint64
	latencyGte10000ms uint64
}

var metrics Metrics

// topQueriesCapacity bounds how many distinct queries the toplist tracks.
// Memory use is bounded to this many query strings regardless of traffic.
const topQueriesCapacity = 1000

// QueryCount is one entry in the queries toplist.
type QueryCount struct {
	Query string `json:"query"`
	Count uint64 `json:"count"`
}

// TopQueries tracks the most frequently run queries using the Space-Saving
// algorithm (Metwally et al., 2005). It keeps at most `capacity` counters; when
// a new query arrives and every slot is taken, the slot with the lowest count
// is evicted and the new query inherits that count + 1. This yields an accurate
// top-K in bounded memory without storing every distinct query.
type TopQueries struct {
	mu       sync.Mutex
	capacity int
	counts   map[string]uint64
}

// NewTopQueries returns a Space-Saving tracker holding up to capacity counters.
func NewTopQueries(capacity int) *TopQueries {
	return &TopQueries{
		capacity: capacity,
		counts:   make(map[string]uint64, capacity),
	}
}

// Record counts one occurrence of query.
func (t *TopQueries) Record(query string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if _, ok := t.counts[query]; ok {
		t.counts[query]++
		return
	}
	if len(t.counts) < t.capacity {
		t.counts[query] = 1
		return
	}

	// All slots full: evict the minimum-count query and let the new one take
	// its place, inheriting min+1. The linear scan is O(capacity); fine for a
	// metrics feature, swap in a stream-summary list if it ever gets hot.
	var minQuery string
	var minCount uint64 = math.MaxUint64
	for q, c := range t.counts {
		if c < minCount {
			minCount = c
			minQuery = q
		}
	}
	delete(t.counts, minQuery)
	t.counts[query] = minCount + 1
}

// Top returns the n most frequent queries, highest count first.
func (t *TopQueries) Top(n int) []QueryCount {
	t.mu.Lock()
	list := make([]QueryCount, 0, len(t.counts))
	for q, c := range t.counts {
		list = append(list, QueryCount{Query: q, Count: c})
	}
	t.mu.Unlock()

	sort.Slice(list, func(i, j int) bool {
		return list[i].Count > list[j].Count
	})
	if len(list) > n {
		list = list[:n]
	}
	return list
}

var topQueries = NewTopQueries(topQueriesCapacity)

// responseWriter wraps http.ResponseWriter to capture status code and response size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	body       bytes.Buffer
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	rw.body.Write(b)
	return rw.ResponseWriter.Write(b)
}

// ReadConfig reads info from config file
func ReadConfig() (Config, error) {
	var configfile = "config.ini"
	var config Config
	if _, err := toml.DecodeFile(configfile, &config); err != nil {
		return config, err
	}
	return config, nil
}

// Request is the data structure posted to the /pathql endpoint
type Request struct {
	Query     string            `json:"query"`
	Params    any               `json:"params"`
	Variables map[string]any    `json:"variables"`
	Paths     map[string]string `json:"paths"`
}

// ErrorResponse is the data structure used to report pathql errors
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// DSNVariable represents a variable in the DSN template
type DSNVariable struct {
	Name         string
	DefaultValue string
	HasDefault   bool
}

// ParseDSNVariables extracts all variables from a DSN template
func ParseDSNVariables(dsn string) []DSNVariable {
	re := regexp.MustCompile(`\{([^}]+)\}`)
	matches := re.FindAllStringSubmatch(dsn, -1)

	var variables []DSNVariable
	for _, match := range matches {
		varSpec := match[1]
		parts := strings.SplitN(varSpec, ":", 2)

		variable := DSNVariable{
			Name:       parts[0],
			HasDefault: len(parts) > 1,
		}

		if variable.HasDefault {
			variable.DefaultValue = parts[1]
		}

		variables = append(variables, variable)
	}

	return variables
}

// ReplaceDSNVariables replaces variables in the DSN with actual values
func ReplaceDSNVariables(dsn string, variables map[string]any) (string, error) {
	dsnVars := ParseDSNVariables(dsn)
	result := dsn

	for _, dsnVar := range dsnVars {
		// Check if variable is provided
		value, provided := variables[dsnVar.Name]

		if !provided {
			if dsnVar.HasDefault {
				// Use default value
				result = strings.Replace(result, fmt.Sprintf("{%s:%s}", dsnVar.Name, dsnVar.DefaultValue), dsnVar.DefaultValue, -1)
			} else {
				// Required variable is missing
				return "", fmt.Errorf("missing required DSN variable: %s", dsnVar.Name)
			}
		} else {
			// Use provided value
			valueStr := fmt.Sprintf("%v", value)
			// Replace both {var} and {var:default} formats
			if dsnVar.HasDefault {
				result = strings.Replace(result, fmt.Sprintf("{%s:%s}", dsnVar.Name, dsnVar.DefaultValue), valueStr, -1)
			} else {
				result = strings.Replace(result, fmt.Sprintf("{%s}", dsnVar.Name), valueStr, -1)
			}
		}
	}

	return result, nil
}

// metricsMiddleware tracks request metrics and logs in verbose mode
func metricsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rw := &responseWriter{
			ResponseWriter: w,
			statusCode:     200,
		}

		next(rw, r)

		duration := time.Since(start).Milliseconds()

		// Track status code
		switch rw.statusCode {
		case 200:
			atomic.AddUint64(&metrics.status200, 1)
		case 400:
			atomic.AddUint64(&metrics.status400, 1)
		case 500:
			atomic.AddUint64(&metrics.status500, 1)
		default:
			atomic.AddUint64(&metrics.statusOther, 1)
		}

		// Track latency bracket
		switch {
		case duration < 1:
			atomic.AddUint64(&metrics.latencyLt1ms, 1)
		case duration < 5:
			atomic.AddUint64(&metrics.latencyLt5ms, 1)
		case duration < 10:
			atomic.AddUint64(&metrics.latencyLt10ms, 1)
		case duration < 50:
			atomic.AddUint64(&metrics.latencyLt50ms, 1)
		case duration < 100:
			atomic.AddUint64(&metrics.latencyLt100ms, 1)
		case duration < 500:
			atomic.AddUint64(&metrics.latencyLt500ms, 1)
		case duration < 1000:
			atomic.AddUint64(&metrics.latencyLt1000ms, 1)
		case duration < 5000:
			atomic.AddUint64(&metrics.latencyLt5000ms, 1)
		case duration < 10000:
			atomic.AddUint64(&metrics.latencyLt10000ms, 1)
		default:
			atomic.AddUint64(&metrics.latencyGte10000ms, 1)
		}

		// Verbose logging
		if config.Verbose {
			log.Printf("%s %d %d %dms\n",
				time.Now().Format(time.RFC3339),
				rw.statusCode,
				rw.body.Len(),
				duration)
		}
	}
}

// MetricsEndpoint handles GET to /metrics
func MetricsEndpoint(w http.ResponseWriter, req *http.Request) {
	response := map[string]any{
		"status_codes": map[string]uint64{
			"200":   atomic.LoadUint64(&metrics.status200),
			"400":   atomic.LoadUint64(&metrics.status400),
			"500":   atomic.LoadUint64(&metrics.status500),
			"other": atomic.LoadUint64(&metrics.statusOther),
		},
		"latency_ms": map[string]uint64{
			"<1":      atomic.LoadUint64(&metrics.latencyLt1ms),
			"<5":      atomic.LoadUint64(&metrics.latencyLt5ms),
			"<10":     atomic.LoadUint64(&metrics.latencyLt10ms),
			"<50":     atomic.LoadUint64(&metrics.latencyLt50ms),
			"<100":    atomic.LoadUint64(&metrics.latencyLt100ms),
			"<500":    atomic.LoadUint64(&metrics.latencyLt500ms),
			"<1000":   atomic.LoadUint64(&metrics.latencyLt1000ms),
			"<5000":   atomic.LoadUint64(&metrics.latencyLt5000ms),
			"<10000":  atomic.LoadUint64(&metrics.latencyLt10000ms),
			">=10000": atomic.LoadUint64(&metrics.latencyGte10000ms),
		},
		"top_queries": topQueries.Top(10),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// PathQlEndpoint handles POST to /pathql
func PathQlEndpoint(w http.ResponseWriter, req *http.Request) {
	request := Request{}
	var response any = nil
	var db *pathsqlx.DB
	var err error

	err = json.NewDecoder(req.Body).Decode(&request)

	if err == nil && request.Query != "" {
		topQueries.Record(request.Query)
	}

	var dsn string
	if err == nil {
		// Replace DSN variables if any
		if request.Variables == nil {
			request.Variables = make(map[string]any)
		}
		dsn, err = ReplaceDSNVariables(config.DSN, request.Variables)
	}

	if err == nil {
		db, err = pathsqlx.Connect(config.Driver, dsn)
	}

	if err == nil {
		query := request.Query

		// Reject slice/array params - only maps are supported
		if _, ok := request.Params.([]any); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			response = ErrorResponse{"Error", "params must be an object, not an array"}
			json.NewEncoder(w).Encode(response)
			return
		}
		// Convert nil params to empty map for sqlx compatibility
		params := request.Params
		if params == nil {
			params = map[string]any{}
		}

		// Convert nil paths to empty map for sqlx compatibility
		paths := request.Paths
		if paths == nil {
			paths = map[string]string{}
		}

		response, err = db.PathQuery(query, params, paths)
	}
	w.Header().Set("Content-Type", "application/json")
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		response = ErrorResponse{"Error", err.Error()}
	}
	json.NewEncoder(w).Encode(response)
}

func main() {
	var err error
	config, err = ReadConfig()
	if err != nil {
		log.Fatal(err)
	}

	// Default to :8000 if Listen is not specified
	if config.Listen == "" {
		config.Listen = ":8000"
	}

	router := mux.NewRouter()
	router.HandleFunc("/pathql", metricsMiddleware(PathQlEndpoint)).Methods("POST")
	router.HandleFunc("/metrics", MetricsEndpoint).Methods("GET")
	log.Fatal(http.ListenAndServe(config.Listen, router))
}
