package log

type Logger interface {
	Printf(format string, v ...interface{})
}

type nullLogger struct{}

func (nullLogger) Printf(format string, v ...interface{}) {
}

func (nullLogger) Fatalf(format string, v ...interface{}) {
}

var DefaultLogger Logger = nullLogger{}
