module github.com/ory/fosite

replace github.com/dgrijalva/jwt-go => github.com/form3tech-oss/jwt-go v3.2.1+incompatible

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

require (
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/dgraph-io/ristretto v0.0.3 // indirect
	github.com/golang/mock v1.4.4
	github.com/gorilla/mux v1.7.3
	github.com/gorilla/websocket v1.4.2
	github.com/magiconair/properties v1.8.1
	github.com/mattn/goveralls v0.0.6
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/oleiade/reflections v1.0.1
	github.com/ory/go-acc v0.2.6
	github.com/ory/go-convenience v0.1.0
	github.com/ory/x v0.0.212
	github.com/parnurzeal/gorequest v0.2.15
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/spf13/afero v1.3.2 // indirect
	github.com/stretchr/testify v1.6.1
	golang.org/x/crypto v0.0.0-20201203163018-be400aefbc4c
	golang.org/x/net v0.0.0-20201021035429-f5854403a974
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	gopkg.in/square/go-jose.v2 v2.5.1
)

go 1.14
