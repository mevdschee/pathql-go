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
	Username string
	Password string
	Database string
	Driver   string
	Address  string
	Port     string
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
		username := config.Username
		password := config.Password
		if user, pass, ok := req.BasicAuth(); ok {
			username = user
			password = pass
		}
		db, err = pathsqlx.Create(username, password, config.Database, config.Driver, config.Address, config.Port)
	}
	if err == nil {
		err = json.NewDecoder(req.Body).Decode(&request)
	}
	if err == nil {
		response, err = db.PathQuery(request.Query, request.Params)
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
