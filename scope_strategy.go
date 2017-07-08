package fosite

import "strings"

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		haystackLen := len(haystack) - 1
		for k, needle := range needles {
			if haystackLen < k {
				return true
			}

			current := haystack[k]
			if current != needle {
				break
			}
		}
	}

	return false
}

func WildcardScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if this == needle {
			return true
		}

		needles := strings.Split(needle, ".")
		haystack := strings.Split(this, ".")
		if len(needles) != len(haystack) {
			continue
		}

		var noteq bool
		for k, needle := range needles {
			current := haystack[k]
			if needle == "*" && len(current) > 0 {
			} else if current != needle {
				noteq = true
				break
			}
		}

		if !noteq {
			return true
		}
	}

	return false
}
