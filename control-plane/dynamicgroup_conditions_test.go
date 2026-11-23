package controlplane

import "testing"

func TestDynamicGroupConditions(t *testing.T) {
	online := true
	m := Machine{Name: "HQ-Box", Alias: "Front Desk", OS: "Windows 11", AgentVersion: "1.3.10+abc", Online: &online}
	properties := map[string]string{"site": "HQ", "empty": ""}
	cases := []struct {
		field, op, value string
		want             bool
	}{
		{"property:site", "equals", "hq", true},
		{"property:Site", "equals", "hq", false},
		{"property:site", "not_equals", "hq", false},
		{"property:site", "not_equals", "DR", true},
		{"property:missing", "not_equals", "DR", false},
		{"property:empty", "exists", "", true},
		{"property:empty", "not_exists", "", false},
		{"property:missing", "exists", "", false},
		{"property:missing", "not_exists", "", true},
		{"os", "contains", "DOWS 11", true},
		{"os", "starts_with", "winDOWS", true},
		{"os", "starts_with", "11", false},
		{"hostname", "equals", "hq-box", true},
		{"hostname", "equals", "front desk", true},
		{"hostname", "not_equals", "front desk", false},
		{"hostname", "not_equals", "hq-box", false},
		{"hostname", "not_equals", "other", true},
		{"hostname", "contains", "DESK", true},
		{"agent_version", "contains", "+ABC", true},
		{"agent_version", "version_at_least", "1.3.9", true},
		{"agent_version", "version_at_least", "1.3.11", false},
		{"online", "equals", "true", true},
		{"online", "equals", "false", false},
	}
	for _, tc := range cases {
		t.Run(tc.field+"/"+tc.op+"/"+tc.value, func(t *testing.T) {
			c := Condition{Field: tc.field, Op: tc.op, Value: tc.value}
			if err := c.validate(); err != nil {
				t.Fatal(err)
			}
			if got := c.matches(m, properties, true); got != tc.want {
				t.Fatalf("matches = %t, want %t", got, tc.want)
			}
		})
	}
	for _, value := range []string{"false", "true"} {
		if (Condition{Field: "online", Op: "equals", Value: value}).matches(m, properties, false) {
			t.Fatalf("unknown presence matched online=%s", value)
		}
	}
}

func TestDynamicVersionAtLeast(t *testing.T) {
	for _, tc := range []struct {
		actual, minimum string
		want            bool
	}{
		{"1.3.10", "1.3.9", true},
		{"1.3.9", "1.3.10", false},
		{"0.1.34+abc", "0.1.34", true},
		{"0.1.34", "0.1.34+xyz", true},
		{"", "0.0.0", false},
		{"broken", "0.0.0", false},
		{"2.0.0-rc.1", "1.0.0", false},
		{"2..1", "1.0.0", false},
		{"99", "broken", false},
		{"1.3", "1.3.0", true},
		{"1.3.0009", "1.3.9", true},
		{"999999999999999999999.0", "999999999999999999998.0", true},
	} {
		if got := dynamicVersionAtLeast(tc.actual, tc.minimum); got != tc.want {
			t.Errorf("%q >= %q = %t, want %t", tc.actual, tc.minimum, got, tc.want)
		}
	}
}

func TestDynamicGroupLegacyPredicateEquivalence(t *testing.T) {
	for _, op := range []string{"exists", "equals"} {
		value := ""
		if op == "equals" {
			value = "HQ"
		}
		legacy := (DynamicGroup{PropertyKey: "site", PropertyValue: value}).effectivePredicate()
		explicit := DynamicGroup{Match: "all", Conditions: []Condition{{Field: "property:site", Op: op, Value: value}}}
		if legacy.Match != explicit.Match || len(legacy.Conditions) != 1 || legacy.Conditions[0] != explicit.Conditions[0] {
			t.Fatalf("legacy predicate = %+v, want %+v", legacy, explicit)
		}
		for _, bag := range []map[string]string{nil, {"site": ""}, {"site": "DR"}, {"site": "hq"}} {
			if legacy.matches(Machine{}, bag, false) != explicit.matches(Machine{}, bag, false) {
				t.Errorf("legacy and explicit %s differ for %v", op, bag)
			}
		}
	}
}
