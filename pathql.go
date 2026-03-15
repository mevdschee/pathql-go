package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"strings"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/mevdschee/pathsqlx"

	_ "github.com/lib/pq"
)

var config Config

// Config contains all configuration
type Config struct {
	Driver string
	DSN    string
	Listen string
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
	Query     string                 `json:"query"`
	Params    interface{}            `json:"params"`
	Variables map[string]interface{} `json:"variables"`
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
func ReplaceDSNVariables(dsn string, variables map[string]interface{}) (string, error) {
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

// PathQlEndpoint handles POST to /pathql
func PathQlEndpoint(w http.ResponseWriter, req *http.Request) {
	request := Request{}
	var response interface{} = nil
	var db *pathsqlx.DB
	var err error

	err = json.NewDecoder(req.Body).Decode(&request)

	var dsn string
	if err == nil {
		// Replace DSN variables if any
		if request.Variables == nil {
			request.Variables = make(map[string]interface{})
		}
		dsn, err = ReplaceDSNVariables(config.DSN, request.Variables)
	}

	if err == nil {
		db, err = pathsqlx.Connect(config.Driver, dsn)
	}

	if err == nil {
		// Reject slice/array params - only maps are supported
		if _, ok := request.Params.([]interface{}); ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			response = ErrorResponse{"Error", "params must be an object, not an array"}
			json.NewEncoder(w).Encode(response)
			return
		}
		// Convert nil params to empty map for sqlx compatibility
		params := request.Params
		if params == nil {
			params = map[string]interface{}{}
		}
		response, err = db.PathQuery(request.Query, params)
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
	router.HandleFunc("/pathql", PathQlEndpoint).Methods("POST")
	log.Fatal(http.ListenAndServe(config.Listen, router))
}
