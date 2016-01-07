package service

import . "github.com/ory-am/fosite"

func NewFosite(store Storage) *Fosite {
	return &Fosite{
		Store: store,
	}
}
