package jwt

import (
	"time"
)

type Mapper interface {
	ToMap() map[string]interface{}
	Add(key string, value interface{})
}

func toString(i interface{}) string {
	if i == nil {
		return ""
	}

	if s, ok := i.(string); ok {
		return s
	}

	return ""
}

func toTime(i interface{}) time.Time {
	if i == nil {
		return time.Time{}
	}

	if t, ok := i.(int64); ok {
		return time.Unix(t, 0)
	} else if t, ok := i.(float64); ok {
		return time.Unix(int64(t), 0)
	}

	return time.Time{}
}
