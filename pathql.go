package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/mevdschee/pathsqlx"
)

// Config contains the database configuration
type Config struct {
	Username string
	Password string
	Database string
	Driver   string
	Address  string
	Port     string
}

// ReadConfig reads info from config file
func ReadConfig() Config {
	var configfile = "config.ini"
	_, err := os.Stat(configfile)
	if err != nil {
		log.Fatal("Config file is missing: ", configfile)
	}
	var config Config
	if _, err := toml.DecodeFile(configfile, &config); err != nil {
		log.Fatal(err)
	}
	return config
}

// Request is the data structure posted to the /pathql endpoint
type Request struct {
	Query  string      `json:"query,omitempty"`
	Params interface{} `json:"params,omitempty"`
}

// PathQlEndpoint handles POST to /pathql
func PathQlEndpoint(w http.ResponseWriter, req *http.Request) {
	var request Request
	var response interface{}
	config := ReadConfig()
	db, err := pathsqlx.Create(config.Username, config.Password, config.Database, config.Driver, config.Address, config.Port)
	if err != nil {
		err = json.NewDecoder(req.Body).Decode(&request)
	}
	if err != nil {
		response, err = db.PathQuery(request.Query, request.Params)
	}
	if err != nil {

	} else {
		json.NewEncoder(w).Encode(response)
	}
}

func main() {
	router := mux.NewRouter()
	router.HandleFunc("/pathql", PathQlEndpoint).Methods("POST")
	log.Fatal(http.ListenAndServe(":8000", router))
}
