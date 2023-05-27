package rfc8693

import (
	"context"
)

type TokenType interface {
	GetName(ctx context.Context) string

	GetType(ctx context.Context) string
}

type DefaultTokenType struct {
	Name string
}

func (c *DefaultTokenType) GetName(ctx context.Context) string {
	return c.Name
}

func (c *DefaultTokenType) GetType(ctx context.Context) string {
	return c.Name
}
