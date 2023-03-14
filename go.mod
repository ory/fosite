module github.com/ory/fosite

replace github.com/dgrijalva/jwt-go => github.com/form3tech-oss/jwt-go v3.2.1+incompatible

replace github.com/gogo/protobuf => github.com/gogo/protobuf v1.3.2

replace github.com/gobuffalo/packr => github.com/gobuffalo/packr v1.30.1

replace github.com/gobuffalo/plush/v4 => github.com/gobuffalo/plush/v4 v4.1.11

replace github.com/gorilla/sessions => github.com/gorilla/sessions v1.2.1

replace github.com/tidwall/gjson => github.com/tidwall/gjson v1.14.1

replace github.com/tidwall/match => github.com/tidwall/match v1.1.1

require (
	github.com/asaskevich/govalidator v0.0.0-20200428143746-21a406dcc535
	github.com/cristalhq/jwt/v4 v4.0.2
	github.com/dgraph-io/ristretto v0.0.3
	github.com/ecordell/optgen v0.0.6
	github.com/golang/mock v1.6.0
	github.com/gorilla/mux v1.8.0
	github.com/gorilla/websocket v1.4.2
	github.com/hashicorp/go-retryablehttp v0.6.8
	github.com/magiconair/properties v1.8.1
	github.com/mattn/goveralls v0.0.6
	github.com/mohae/deepcopy v0.0.0-20170929034955-c48cc78d4826
	github.com/oleiade/reflections v1.0.1
	github.com/ory/go-acc v0.2.6
	github.com/ory/go-convenience v0.1.0
	github.com/ory/x v0.0.214
	github.com/parnurzeal/gorequest v0.2.15
	github.com/pborman/uuid v1.2.0
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.0
	github.com/tidwall/gjson v1.7.1
	golang.org/x/crypto v0.1.0
	golang.org/x/net v0.7.0
	golang.org/x/oauth2 v0.0.0-20200107190931-bf48bf16ab8d
	golang.org/x/text v0.7.0
	gopkg.in/square/go-jose.v2 v2.5.2-0.20210529014059-a5c7eec3c614
)

replace github.com/dgraph-io/ristretto => github.com/ory/ristretto v0.1.1-0.20211108053508-297c39e6640f

require (
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/dave/jennifer v1.4.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.0 // indirect
	github.com/fsnotify/fsnotify v1.4.9 // indirect
	github.com/golang/glog v0.0.0-20160126235308-23def4e6c14b // indirect
	github.com/golang/protobuf v1.4.2 // indirect
	github.com/google/uuid v1.1.2 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/mitchellh/mapstructure v1.3.2 // indirect
	github.com/moul/http2curl v0.0.0-20170919181001-9ac6cf4d929b // indirect
	github.com/ory/viper v1.7.5 // indirect
	github.com/pelletier/go-toml v1.8.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/spf13/afero v1.3.2 // indirect
	github.com/spf13/cast v1.3.2-0.20200723214538-8d17101741c8 // indirect
	github.com/spf13/cobra v1.0.0 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/subosito/gotenv v1.2.0 // indirect
	github.com/tidwall/match v1.1.1 // indirect
	github.com/tidwall/pretty v1.2.0 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220419223038-86c51ed26bb4 // indirect
	golang.org/x/sys v0.5.0 // indirect
	golang.org/x/tools v0.1.12 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/protobuf v1.25.0 // indirect
	gopkg.in/ini.v1 v1.57.0 // indirect
	gopkg.in/yaml.v2 v2.3.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20200615113413-eeeca48fe776 // indirect
)

go 1.17
