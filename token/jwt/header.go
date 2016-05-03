package jwt

// HeaderContext is the context for a jwt header.
type Headers struct {
	Extra map[string]interface{}
}

func (h *Headers) ToMap() map[string]interface{} {
	var filter = map[string]bool{"alg": true, "typ": true}
	var extra = map[string]interface{}{}

	// filter known values from extra.
	for k, v := range h.Extra {
		if _, ok := filter[k]; !ok {
			extra[k] = v
		}
	}

	return extra
}

func (h *Headers) Add(key string, value interface{}) {
	if h.Extra == nil {
		h.Extra = make(map[string]interface{})
	}
	h.Extra[key] = value
}

func (h *Headers) Get(key string) interface{} {
	return h.Extra[key]
}
