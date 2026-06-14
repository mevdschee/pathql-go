package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"dbml-tools/introspect"

	"github.com/mevdschee/pathql-go/internal/config"
)

func TestSchemaEngineMapping(t *testing.T) {
	eng, name, ok := schemaEngine("postgres")
	if !ok || eng != introspect.EnginePostgres || name != "public" {
		t.Fatalf("postgres: got engine=%v name=%q ok=%v", eng, name, ok)
	}
	if _, _, ok := schemaEngine("mysql"); ok {
		t.Errorf("mysql should be unsupported for schema reflection for now")
	}
	if _, _, ok := schemaEngine("sqlite"); ok {
		t.Errorf("sqlite should be unsupported for schema reflection")
	}
}

// TestSchemaEndpointUnsupportedDriver verifies a non-postgres driver returns 501
// before any database work is attempted.
func TestSchemaEndpointUnsupportedDriver(t *testing.T) {
	prev := cfg
	defer func() { cfg = prev }()
	cfg = &config.Config{Driver: "mysql"}

	rec := httptest.NewRecorder()
	SchemaEndpoint(rec, httptest.NewRequest(http.MethodGet, "/schema", nil))
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501 for non-postgres driver, got %d", rec.Code)
	}
}
