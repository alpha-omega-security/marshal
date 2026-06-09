package packages

import (
	"strings"
)

// normalizeRepoURL turns a repository URL into a canonical https form so
// the same repo doesn't end up as multiple rows under different protocols.
// Rules:
//
//   - strip a trailing slash
//   - strip a trailing `.git` suffix (or `.git/`)
//   - rewrite `git://`, `git+https://`, `git+ssh://`, `ssh://`, `http://`
//     prefixes to `https://`
//   - rewrite the scp-like `git@host:org/repo.git` form to
//     `https://host/org/repo`
//   - drop `git@` user info from the authority component
//
// Empty input passes through unchanged. We don't validate that the result
// actually points at a host; that's the forge's job at clone time.
func normalizeRepoURL(s string) string {
	if s == "" {
		return s
	}
	s = strings.TrimSpace(s)

	// scp-like: git@github.com:foo/bar.git
	if !strings.Contains(s, "://") && strings.Contains(s, "@") && strings.Contains(s, ":") {
		at := strings.Index(s, "@")
		colon := strings.Index(s, ":")
		if at >= 0 && colon > at {
			host := s[at+1 : colon]
			path := s[colon+1:]
			s = "https://" + host + "/" + path
		}
	}

	// scheme rewrites: anything that isn't already https becomes https
	switch {
	case strings.HasPrefix(s, "git+https://"):
		s = "https://" + strings.TrimPrefix(s, "git+https://")
	case strings.HasPrefix(s, "git+ssh://"):
		s = "https://" + strings.TrimPrefix(s, "git+ssh://")
	case strings.HasPrefix(s, "git://"):
		s = "https://" + strings.TrimPrefix(s, "git://")
	case strings.HasPrefix(s, "ssh://"):
		s = "https://" + strings.TrimPrefix(s, "ssh://")
	case strings.HasPrefix(s, "http://"):
		s = "https://" + strings.TrimPrefix(s, "http://")
	}

	// drop git@ userinfo on the authority component
	s = strings.Replace(s, "https://git@", "https://", 1)

	// strip trailing slash, then .git, then trailing slash again so
	// `https://h/p.git/` collapses cleanly.
	s = strings.TrimSuffix(s, "/")
	s = strings.TrimSuffix(s, ".git")
	s = strings.TrimSuffix(s, "/")
	return s
}
