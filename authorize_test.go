package fosite

func TestAuthorizeCode() {

	ar := HandleAuthorizeRequest()
	ar.Extra = ...

	resp := ar.Finish()
	ar.Write()
}