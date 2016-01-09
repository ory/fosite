package fosite

type AccessResponder interface {
	Set(key string, value interface{})
	Get(key string) interface{}
}
