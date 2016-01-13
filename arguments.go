package fosite

type Arguments []string

func (r Arguments) Has(item string) bool {
	return StringInSlice(item, r)
}
