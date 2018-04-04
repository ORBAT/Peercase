package log

import (
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func DevLogger(name string) *zap.Logger {
	conf := zap.NewDevelopmentConfig()
	conf.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	l, err := conf.Build(zap.AddCaller())
	if err != nil {
		panic(err)
	}
	return l.Named(name)
}
