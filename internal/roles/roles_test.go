package roles

import (
	"reflect"
	"testing"
)

func TestRoleName(t *testing.T) {
	tests := []struct {
		name    string
		prefix  string
		userID  int64
		want    string
		wantErr bool
	}{
		{
			name:   "simple",
			prefix: "pathql_r_",
			userID: 42,
			want:   "pathql_r_42",
		},
		{
			name:   "leading underscore prefix",
			prefix: "_r",
			userID: 1,
			want:   "_r1",
		},
		{
			name:    "invalid prefix with uppercase",
			prefix:  "Pathql_",
			userID:  1,
			wantErr: true,
		},
		{
			name:    "invalid prefix starting with digit",
			prefix:  "1r_",
			userID:  1,
			wantErr: true,
		},
		{
			name:    "invalid prefix with dash",
			prefix:  "pathql-r-",
			userID:  1,
			wantErr: true,
		},
		{
			name:    "empty prefix",
			prefix:  "",
			userID:  1,
			wantErr: true,
		},
		{
			// A 63-char prefix plus any id overflows the 63-byte limit.
			name:    "name too long",
			prefix:  "a23456789012345678901234567890123456789012345678901234567890_xyz",
			userID:  1000,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RoleName(tt.prefix, tt.userID)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got name %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("RoleName(%q, %d) = %q, want %q", tt.prefix, tt.userID, got, tt.want)
			}
		})
	}
}

func TestComputeInvalidPrefix(t *testing.T) {
	_, err := Compute(Inputs{
		Prefix:     "BAD-PREFIX",
		ReaderRole: "pathql_readers",
	})
	if err == nil {
		t.Fatal("expected error for invalid prefix, got nil")
	}
}

func TestCompute(t *testing.T) {
	const prefix = "pathql_r_"
	const reader = "pathql_readers"

	tests := []struct {
		name string
		in   Inputs
		want Plan
	}{
		{
			name: "create missing role",
			in: Inputs{
				Prefix:          prefix,
				ReaderRole:      reader,
				ExistingRoles:   nil,
				ExpectedUserIDs: []int64{7},
				ReaderMembers:   nil,
			},
			want: Plan{
				Create:      []string{"pathql_r_7"},
				GrantReader: []string{"pathql_r_7"},
				Drop:        nil,
				DDL: []string{
					`CREATE ROLE "pathql_r_7" LOGIN NOSUPERUSER NOCREATEROLE INHERIT;`,
					`GRANT "pathql_readers" TO "pathql_r_7";`,
				},
			},
		},
		{
			name: "drop orphan",
			in: Inputs{
				Prefix:          prefix,
				ReaderRole:      reader,
				ExistingRoles:   []string{"pathql_r_9"},
				ExpectedUserIDs: nil,
				ReaderMembers:   map[string]bool{"pathql_r_9": true},
			},
			want: Plan{
				Create:      nil,
				GrantReader: nil,
				Drop:        []string{"pathql_r_9"},
				DDL: []string{
					`DROP ROLE IF EXISTS "pathql_r_9";`,
				},
			},
		},
		{
			name: "grant missing membership on existing role",
			in: Inputs{
				Prefix:          prefix,
				ReaderRole:      reader,
				ExistingRoles:   []string{"pathql_r_3"},
				ExpectedUserIDs: []int64{3},
				ReaderMembers:   nil, // exists but lacks the reader grant
			},
			want: Plan{
				Create:      nil,
				GrantReader: []string{"pathql_r_3"},
				Drop:        nil,
				DDL: []string{
					`GRANT "pathql_readers" TO "pathql_r_3";`,
				},
			},
		},
		{
			name: "no-op when fully in sync",
			in: Inputs{
				Prefix:          prefix,
				ReaderRole:      reader,
				ExistingRoles:   []string{"pathql_r_1", "pathql_r_2"},
				ExpectedUserIDs: []int64{1, 2},
				ReaderMembers:   map[string]bool{"pathql_r_1": true, "pathql_r_2": true},
			},
			want: Plan{
				Create:      nil,
				GrantReader: nil,
				Drop:        nil,
				DDL:         []string{},
			},
		},
		{
			name: "prefix guard ignores unmanaged existing role",
			in: Inputs{
				Prefix:     prefix,
				ReaderRole: reader,
				// postgres, the reader role, and the bare prefix must never be
				// dropped or appear anywhere in the plan.
				ExistingRoles:   []string{"postgres", "pathql_readers", "pathql_r_", "other_role"},
				ExpectedUserIDs: nil,
				ReaderMembers:   nil,
			},
			want: Plan{
				Create:      nil,
				GrantReader: nil,
				Drop:        nil,
				DDL:         []string{},
			},
		},
		{
			name: "deterministic ordering of mixed actions",
			in: Inputs{
				Prefix:     prefix,
				ReaderRole: reader,
				// Out-of-order ids and existing roles to prove sorting.
				ExistingRoles:   []string{"pathql_r_30", "pathql_r_20", "pathql_r_5"},
				ExpectedUserIDs: []int64{20, 10, 5},
				// r_5 exists with membership (skip), r_20 exists without (grant),
				// r_10 is new (create+grant), r_30 is orphan (drop).
				ReaderMembers: map[string]bool{"pathql_r_5": true},
			},
			want: Plan{
				Create:      []string{"pathql_r_10"},
				GrantReader: []string{"pathql_r_10", "pathql_r_20"},
				Drop:        []string{"pathql_r_30"},
				DDL: []string{
					`CREATE ROLE "pathql_r_10" LOGIN NOSUPERUSER NOCREATEROLE INHERIT;`,
					`GRANT "pathql_readers" TO "pathql_r_10";`,
					`GRANT "pathql_readers" TO "pathql_r_20";`,
					`DROP ROLE IF EXISTS "pathql_r_30";`,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Compute(tt.in)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("Compute() mismatch\n got: %#v\nwant: %#v", got, tt.want)
			}
		})
	}
}

// TestComputeNeverTouchesReaderRole asserts the reader role is never created or
// dropped even if it somehow shares the managed prefix, and that an unmanaged
// role can never reach Drop or DDL regardless of expected state.
func TestComputeNeverDropsUnmanaged(t *testing.T) {
	plan, err := Compute(Inputs{
		Prefix:          "pathql_r_",
		ReaderRole:      "pathql_readers",
		ExistingRoles:   []string{"admin", "pathql_readers", "totally_unmanaged"},
		ExpectedUserIDs: nil,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(plan.Drop) != 0 {
		t.Errorf("expected no drops, got %v", plan.Drop)
	}
	if len(plan.DDL) != 0 {
		t.Errorf("expected no DDL, got %v", plan.DDL)
	}
}

// TestComputeDeterministic runs the same input repeatedly to confirm the output
// does not depend on Go map iteration order.
func TestComputeDeterministic(t *testing.T) {
	in := Inputs{
		Prefix:          "pathql_r_",
		ReaderRole:      "pathql_readers",
		ExistingRoles:   []string{"pathql_r_8", "pathql_r_1", "pathql_r_4"},
		ExpectedUserIDs: []int64{1, 2, 3},
		ReaderMembers:   map[string]bool{"pathql_r_1": true},
	}

	first, err := Compute(in)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for i := 0; i < 50; i++ {
		got, err := Compute(in)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("non-deterministic output on iteration %d\n got: %#v\nwant: %#v", i, got, first)
		}
	}
}
