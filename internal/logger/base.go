package logger

import (
	"log"
	"os"
)

var Logger *log.Logger

func init() {
	Logger = log.New(os.Stderr, "", log.Ldate|log.Ltime|log.Llongfile|log.LUTC)
}
