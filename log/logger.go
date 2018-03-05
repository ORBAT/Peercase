package log

import (
	"go.uber.org/zap"
)

var DevLogger *zap.SugaredLogger

func init() {
	l, err := zap.NewDevelopment(zap.AddCaller())
	if err != nil {
		panic(err)
	}
	DevLogger = l.Sugar()
}
