package db

import "testing"

// TestIsEffective covers the three branches: range matches, range misses,
// and the conservative fallbacks (empty / unparseable). vers parses npm
// semver natively; npm covers the bulk of our test data.
func TestIsEffective(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name      string
		rangeStr  string
		ecosystem string
		observed  []string
		want      bool
	}{
		{name: "match below upper bound", rangeStr: "< 4.17.12", ecosystem: "npm", observed: []string{"4.17.10"}, want: true},
		{name: "no match above upper bound", rangeStr: "< 4.17.12", ecosystem: "npm", observed: []string{"4.17.21"}, want: false},
		{name: "match in span", rangeStr: ">= 1.0.0 < 2.0.0", ecosystem: "npm", observed: []string{"1.5.0"}, want: true},
		{name: "second of two matches", rangeStr: "< 1.0.0", ecosystem: "npm", observed: []string{"2.0.0", "0.9.0"}, want: true},
		{name: "no observed versions defaults to effective", rangeStr: "< 1.0.0", ecosystem: "npm", observed: nil, want: true},
		{name: "empty range defaults to effective", rangeStr: "", ecosystem: "npm", observed: []string{"1.0.0"}, want: true},
	}
	for _, c := range cases {
		got := isEffective(c.rangeStr, c.ecosystem, c.observed)
		if got != c.want {
			t.Errorf("%s: isEffective(%q,%q,%v)=%v want %v", c.name, c.rangeStr, c.ecosystem, c.observed, got, c.want)
		}
	}
}
