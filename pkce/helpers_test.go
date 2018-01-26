package pkce

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsValid(t *testing.T) {
	for k, c := range []struct {
		given string
		valid bool
	}{
		{
			given: "",
			valid: false,
		},
		{ // Too short
			given: "tFQvz4e1umkzHgeWAR4lGOy7mI4dbCrzPwvYlqlxpx",
			valid: false,
		},
		{
			given: "tFQvz4e1umkzHgeWAR4lGOy7mI4dbCrzPwvYlqlxpx6",
			valid: true,
		},
		{
			given: "pq6eJXUdXhEDNqwDHbFOwx5BGtYgKWXdhyMLEHsOLPBvwLhrRCyBmVWfB4x6Nkd4CXyxLAr1tnfCjs9boH4UrQeFkkoNKXLllJhKNs9mvleFWw6TUsF04WDrLA23xBod",
			valid: true,
		},
		{ // To long
			given: "pq6eJXUdXhEDNqwDHbFOwx5BGtYgKWXdhyMLEHsOLPBvwLhrRCyBmVWfB4x6Nkd4CXyxLAr1tnfCjs9boH4UrQeFkkoNKXLllJhKNs9mvleFWw6TUsF04WDrLA23xBod0",
			valid: false,
		},
	} {
		t.Run(fmt.Sprintf("case=%d", k), func(t *testing.T) {
			valid := IsValid(c.given)
			assert.Equal(t, c.valid, valid, fmt.Sprintf("Should be as expected, result: %t, expected: %t", valid, c.valid))
		})
	}
}
