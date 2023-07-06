package utils

import (
	"log"
)

func HandleCriticalError(e error) {
	if e != nil {
		log.Panic(e)
	}
}
