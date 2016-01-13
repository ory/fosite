package enigma

import (
	"testing"
	"time"

	"github.com/ory-am/fosite/enigma/jwthelper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMerge(t *testing.T) {
	for k, c := range [][]map[string]interface{}{
		{
			{"foo": "bar"},
			{"baz": "bar"},
			{"foo": "bar", "baz": "bar"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz"},
			{"foo": "bar"},
		},
		{
			{},
			{"foo": "baz"},
			{"foo": "baz"},
		},
		{
			{"foo": "bar"},
			{"foo": "baz", "bar": "baz"},
			{"foo": "bar", "bar": "baz"},
		},
	} {
		assert.EqualValues(t, c[2], merge(c[0], c[1]), "Case %d", k)
	}
}

func TestLoadCertificate(t *testing.T) {
	for _, c := range TestCertificates {
		out, err := LoadCertificate(c[0])
		assert.Nil(t, err)
		assert.Equal(t, c[1], string(out))
	}
	_, err := LoadCertificate("")
	assert.NotNil(t, err)
	_, err = LoadCertificate("foobar")
	assert.NotNil(t, err)
}

func TestRejectsAlgAndTypHeader(t *testing.T) {
	for _, c := range []map[string]interface{}{
		{"alg": "foo"},
		{"typ": "foo"},
		{"typ": "foo", "alg": "foo"},
	} {
		j := JWTEnigma{
			PrivateKey: []byte(TestCertificates[0][1]),
			PublicKey:  []byte(TestCertificates[1][1]),
			Claims:     make(map[string]interface{}),
			Headers:    c,
		}
		_, err := j.GenerateChallenge([]byte(""))
		assert.NotNil(t, err)
	}
}

func TestGenerateJWT(t *testing.T) {
	claims, err := jwthelper.NewClaimsContext("fosite", "peter", "group0",
		time.Now().Add(time.Hour), time.Now(), time.Now(), make(map[string]interface{}))
	j := JWTEnigma{
		PrivateKey: []byte(TestCertificates[0][1]),
		PublicKey:  []byte(TestCertificates[1][1]),
		Claims:     *claims,
		Headers:    make(map[string]interface{}),
	}

	challenge, err := j.GenerateChallenge([]byte(""))
	require.Nil(t, err, "%s", err)
	require.NotNil(t, challenge)
	t.Logf("%s.%s", challenge.Key, challenge.Signature)

	err = j.ValidateChallenge([]byte(""), challenge)
	require.Nil(t, err, "%s", err)

	challenge.FromString(challenge.String())
	t.Logf("%s", challenge.Key)
	err = j.ValidateChallenge([]byte(""), challenge)
	require.Nil(t, err, "%s", err)

	// Lets change the public certificate to a different public one...
	t.Logf("Old: %s", j.PublicKey)
	j.PublicKey = []byte("new")
	t.Logf("New: %s", j.PublicKey)

	err = j.ValidateChallenge([]byte(""), challenge)
	require.NotNil(t, err, "%s", err)
}

func TestPlainJWTToken(t *testing.T) {
	j := JWTEnigma{
		PrivateKey: []byte(TestCertificates[0][1]),
		PublicKey:  []byte(TestCertificates[1][1]),
		Claims:     make(map[string]interface{}),
		Headers:    make(map[string]interface{}),
	}

	challenge := &Challenge{}
	challenge.FromString("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJncm91cDAiLCJjdXN0b21fcGFyYW10ZXIiOiJjdXN0b21fdmFsdWUuIFlvdSBjYW4gcHV0IHdoYXRldmVyIHlvdSB3YW50IGhlcmUuLiIsImV4cCI6MTQ1MjcyMjE0MSwiaWF0IjoxNDUyNzE4NTQxLCJpc3MiOiJmb3NpdGUiLCJuYmYiOjE0NTI3MTg1NDEsInN1YiI6InBldGVyIn0.lp_FsFQRmz76ACj88qW54y3rVJqZcMixkVEYNtCXoDZZDqilraDEtybpX1eGaDgav2DwIYxS4Zweo3HadreAoour9UhYxjaQD1VDwahEnNR_zz2qjFouNvTjA6Ac9vxW14Ne0HE1Y_CCC-93zm5JKr5tSnfsaOzTvT7fgm76fyooGtdiHSDAWNrc4TmYKalS5yFk2YcZCWoVGoDNp1ZA6KfxsZf4-XD0EMNUpaxudcRlAttxlqIVLPFs4g-PYyoYXvTgdtA6Hokc1POc7D8STpHvl11huDQWU1fsm4mnaP2mmHsG44XqqsHOhnH0i5nWSrDkot9W5Htg51wpHL-_MQ")
	require.NotEmpty(t, challenge.Key)
	require.NotEmpty(t, challenge.Signature)

	err := j.ValidateChallenge([]byte(""), challenge)
	require.Nil(t, err, "%s", err)
}

func TestValidateSignatureRejectsJWT(t *testing.T) {
	var err error
	claims, err := jwthelper.NewClaimsContext("fosite", "peter", "group0",
		time.Now().Add(time.Hour), time.Now(), time.Now(), make(map[string]interface{}))
	j := JWTEnigma{
		PrivateKey: []byte(TestCertificates[0][1]),
		PublicKey:  []byte(TestCertificates[1][1]),
		Claims:     *claims,
		Headers:    make(map[string]interface{}),
	}
	token := new(Challenge)
	for k, c := range []string{
		"",
		" ",
		"foo.bar",
		"foo.",
		".foo",
	} {
		token.FromString(c)
		err = j.ValidateChallenge([]byte(""), token)
		assert.NotNil(t, err, "%s", err)
		t.Logf("Passed test case %d", k)
	}
}
