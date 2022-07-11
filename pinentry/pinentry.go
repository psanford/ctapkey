package pinentry

type PinEntry interface {
	ConfirmPresence(prompt string, id []byte) (chan Result, error)
	GetPin(prompt string, id []byte) (chan Result, error)
}

type Result struct {
	OK    bool
	Pin   string
	Error error
}
