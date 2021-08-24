package i18n

import (
	"fmt"

	"golang.org/x/text/language"
)

// MessageCatalog declares the interface to get globalized messages
type MessageCatalog interface {
	GetMessage(ID string, tag language.Tag, v ...interface{}) string
}

// GetMessage is a helper func to get the translated message based on
// the message ID and lang. If no matching message is found, it uses
// ID as the message itself.
func GetMessage(c MessageCatalog, ID string, tag language.Tag, v ...interface{}) string {
	if c != nil {
		if s := c.GetMessage(ID, tag, v...); s != "" {
			return s
		}
	}

	return fmt.Sprintf(ID, v...)
}
