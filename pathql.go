package main

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/mevdschee/pathsqlx"

	_ "github.com/lib/pq"
)

// Config contains all configuration
type Config struct {
	Driver string
	DSN    string
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
	Query  string      `json:"query"`
	Params interface{} `json:"params"`
}

// ErrorResponse is the data structure used to report pathql errors
type ErrorResponse struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// PathQlEndpoint handles POST to /pathql
func PathQlEndpoint(w http.ResponseWriter, req *http.Request) {
	request := Request{}
	var response interface{} = nil
	var db *pathsqlx.DB
	config, err := ReadConfig()
	if err == nil {
		db, err = pathsqlx.Connect(config.Driver, config.DSN)
	}
	if err == nil {
		err = json.NewDecoder(req.Body).Decode(&request)
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
	router := mux.NewRouter()
	router.HandleFunc("/pathql", PathQlEndpoint).Methods("POST")
	log.Fatal(http.ListenAndServe(":8000", router))
}
