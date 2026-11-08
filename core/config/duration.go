package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// maxDays bounds the "Nd" form so a day count can never overflow a Duration
// (about 106751 days fit) and an expire of years is caught as a typo.
const maxDays = 3650

// ParseDuration accepts Go durations ("90s", "8h", "1h30m") and whole days
// ("7d", up to 3650). The result is always positive; surrounding whitespace,
// fractions of a day and mixed forms such as "1d1h" are refused.
func ParseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		digits := strings.TrimSuffix(s, "d")
		n, err := strconv.Atoi(digits)
		if err != nil || !isASCIIDigits(digits) || n <= 0 || n > maxDays {
			return 0, fmt.Errorf("invalid duration %q (days are 1d to %dd)", s, maxDays)
		}
		return time.Duration(n) * 24 * time.Hour, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("invalid duration %q", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("duration %q must be positive", s)
	}
	return d, nil
}

// isASCIIDigits rejects signs ("+1d", "-1d") and anything strconv might
// otherwise accept in front of the day count.
func isASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
