package main

import (
	"testing"
)

func TestParseDSNVariables(t *testing.T) {
	tests := []struct {
		name     string
		dsn      string
		expected []DSNVariable
	}{
		{
			name: "simple variable without default",
			dsn:  "user={username} password={password}",
			expected: []DSNVariable{
				{Name: "username", HasDefault: false},
				{Name: "password", HasDefault: false},
			},
		},
		{
			name: "variable with default value",
			dsn:  "host={host:localhost} port={port:5432}",
			expected: []DSNVariable{
				{Name: "host", DefaultValue: "localhost", HasDefault: true},
				{Name: "port", DefaultValue: "5432", HasDefault: true},
			},
		},
		{
			name: "mixed variables with and without defaults",
			dsn:  "host={host:localhost} user={username} dbname={dbname:pathql}",
			expected: []DSNVariable{
				{Name: "host", DefaultValue: "localhost", HasDefault: true},
				{Name: "username", HasDefault: false},
				{Name: "dbname", DefaultValue: "pathql", HasDefault: true},
			},
		},
		{
			name:     "no variables",
			dsn:      "host=localhost port=5432",
			expected: []DSNVariable{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ParseDSNVariables(tt.dsn)
			if len(result) != len(tt.expected) {
				t.Fatalf("expected %d variables, got %d", len(tt.expected), len(result))
			}
			for i, v := range result {
				if v.Name != tt.expected[i].Name {
					t.Errorf("variable %d: expected name %s, got %s", i, tt.expected[i].Name, v.Name)
				}
				if v.HasDefault != tt.expected[i].HasDefault {
					t.Errorf("variable %d: expected HasDefault %v, got %v", i, tt.expected[i].HasDefault, v.HasDefault)
				}
				if v.DefaultValue != tt.expected[i].DefaultValue {
					t.Errorf("variable %d: expected DefaultValue %s, got %s", i, tt.expected[i].DefaultValue, v.DefaultValue)
				}
			}
		})
	}
}

func TestReplaceDSNVariables(t *testing.T) {
	tests := []struct {
		name      string
		dsn       string
		variables map[string]interface{}
		expected  string
		wantError bool
		errorMsg  string
	}{
		{
			name: "all required variables provided",
			dsn:  "user={username} password={password}",
			variables: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expected:  "user=testuser password=testpass",
			wantError: false,
		},
		{
			name: "missing required variable",
			dsn:  "user={username} password={password}",
			variables: map[string]interface{}{
				"password": "testpass",
			},
			wantError: true,
			errorMsg:  "missing required DSN variable: username",
		},
		{
			name: "case sensitivity - wrong casing",
			dsn:  "user={username} password={password}",
			variables: map[string]interface{}{
				"Username": "testuser",
				"password": "testpass",
			},
			wantError: true,
			errorMsg:  "missing required DSN variable: username",
		},
		{
			name: "case sensitivity - correct casing",
			dsn:  "user={username} password={password}",
			variables: map[string]interface{}{
				"username": "testuser",
				"password": "testpass",
			},
			expected:  "user=testuser password=testpass",
			wantError: false,
		},
		{
			name:      "default values - not provided",
			dsn:       "host={host:localhost} port={port:5432}",
			variables: map[string]interface{}{},
			expected:  "host=localhost port=5432",
			wantError: false,
		},
		{
			name: "default values - override with provided value",
			dsn:  "host={host:localhost} port={port:5432}",
			variables: map[string]interface{}{
				"host": "remotehost",
				"port": "3306",
			},
			expected:  "host=remotehost port=3306",
			wantError: false,
		},
		{
			name: "mixed required and optional variables",
			dsn:  "host={host:localhost} port={port:5432} user={username} password={password} dbname={dbname:pathql}",
			variables: map[string]interface{}{
				"username": "pathql",
				"password": "pathql",
			},
			expected:  "host=localhost port=5432 user=pathql password=pathql dbname=pathql",
			wantError: false,
		},
		{
			name: "mixed with some overridden defaults",
			dsn:  "host={host:localhost} port={port:5432} user={username} password={password} dbname={dbname:pathql}",
			variables: map[string]interface{}{
				"username": "pathql",
				"password": "pathql",
				"host":     "192.168.1.100",
				"dbname":   "production",
			},
			expected:  "host=192.168.1.100 port=5432 user=pathql password=pathql dbname=production",
			wantError: false,
		},
		{
			name: "postgres DSN format",
			dsn:  "host={host:localhost} port={port:5432} user={username} password={password} dbname={dbname:pathql} sslmode=disable",
			variables: map[string]interface{}{
				"username": "pathql",
				"password": "pathql",
			},
			expected:  "host=localhost port=5432 user=pathql password=pathql dbname=pathql sslmode=disable",
			wantError: false,
		},
		{
			name:      "no variables in DSN",
			dsn:       "host=localhost port=5432 user=fixed password=fixed",
			variables: map[string]interface{}{},
			expected:  "host=localhost port=5432 user=fixed password=fixed",
			wantError: false,
		},
		{
			name: "numeric values converted to strings",
			dsn:  "port={port}",
			variables: map[string]interface{}{
				"port": 5432,
			},
			expected:  "port=5432",
			wantError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ReplaceDSNVariables(tt.dsn, tt.variables)

			if tt.wantError {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if err.Error() != tt.errorMsg {
					t.Errorf("expected error message '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected DSN:\n%s\ngot:\n%s", tt.expected, result)
				}
			}
		})
	}
}

func TestReplaceDSNVariables_RealWorldExample(t *testing.T) {
	dsn := "host={host:localhost} port={port:5432} user={username} password={password} dbname={dbname:pathql} sslmode=disable"

	t.Run("minimal required variables", func(t *testing.T) {
		variables := map[string]interface{}{
			"username": "pathql",
			"password": "pathql",
		}
		result, err := ReplaceDSNVariables(dsn, variables)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "host=localhost port=5432 user=pathql password=pathql dbname=pathql sslmode=disable"
		if result != expected {
			t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
		}
	})

	t.Run("all variables specified", func(t *testing.T) {
		variables := map[string]interface{}{
			"host":     "db.example.com",
			"port":     "3306",
			"username": "admin",
			"password": "secret",
			"dbname":   "production",
		}
		result, err := ReplaceDSNVariables(dsn, variables)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := "host=db.example.com port=3306 user=admin password=secret dbname=production sslmode=disable"
		if result != expected {
			t.Errorf("expected:\n%s\ngot:\n%s", expected, result)
		}
	})

	t.Run("missing password fails", func(t *testing.T) {
		variables := map[string]interface{}{
			"username": "pathql",
		}
		_, err := ReplaceDSNVariables(dsn, variables)
		if err == nil {
			t.Fatal("expected error for missing password")
		}
		if err.Error() != "missing required DSN variable: password" {
			t.Errorf("unexpected error message: %v", err)
		}
	})
}
