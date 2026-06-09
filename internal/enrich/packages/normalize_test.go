package packages

import "testing"

func TestNormalizeRepoURL(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want string
	}{
		{"https://github.com/foo/bar", "https://github.com/foo/bar"},
		{"https://github.com/foo/bar/", "https://github.com/foo/bar"},
		{"https://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"https://github.com/foo/bar.git/", "https://github.com/foo/bar"},
		{"git://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"git://git.coolaj86.com/coolaj86/atob.js.git", "https://git.coolaj86.com/coolaj86/atob.js"},
		{"git+https://github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"git+ssh://git@github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"ssh://git@github.com/foo/bar.git", "https://github.com/foo/bar"},
		{"git@github.com:foo/bar.git", "https://github.com/foo/bar"},
		{"http://github.com/foo/bar", "https://github.com/foo/bar"},
		{"", ""},
	}
	for _, c := range cases {
		got := normalizeRepoURL(c.in)
		if got != c.want {
			t.Errorf("normalizeRepoURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
