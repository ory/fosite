package jwt

// HeaderContext is the context for a jwt header.
type Header struct {
	Extra map[string]interface{}
}

func (h *Header) ToMap() map[string]interface{} {
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

func (h *Header) Add(key string, value interface{}) {
	if h.Extra == nil {
		h.Extra = make(map[string]interface{})
	}
	h.Extra[key] = value
}

func (h *Header) Get(key string) interface{} {
	return h.Extra[key]
}
