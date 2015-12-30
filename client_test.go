package fosite

import "testing"
import "github.com/ory-am/fosite/hash"

func TestSecureClient(t *testing.T) {
	secret, _ := hash.BCrypt{WorkFactor: 5}
	redirect := []string{"foo", "bar"}
	sc := &SecureClient{
		ID: "1",
		Secret: secret,
		RedirectURIs: []
	}
}