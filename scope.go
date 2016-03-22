package fosite

func (f *Fosite) GetMandatoryScope() string {
	if f.MandatoryScope == "" {
		return DefaultMandatoryScope
	}
	return f.MandatoryScope
}
