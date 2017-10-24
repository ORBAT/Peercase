package log

import (
	"github.com/go-kit/kit/log"
	"os"
)

var DevLogger log.Logger

type Logger = log.Logger

func init() {
	DevLogger = log.With(log.NewLogfmtLogger(log.NewSyncWriter(os.Stdout)),
		"ts", log.DefaultTimestampUTC,
			"caller", log.DefaultCaller)
}

func WithComponent(logger log.Logger, component string) Logger {
	return log.With(logger, "component", component)
}