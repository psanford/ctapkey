package main

import (
	"context"
	"log"

	"github.com/psanford/ctapkey"
	"github.com/psanford/ctapkey/examples/u2f-soft-key/memory"
	"github.com/psanford/ctapkey/examples/u2f-soft-key/pinentry"
)

func main() {

	signer, err := memory.New()
	if err != nil {
		panic(err)
	}

	s := ctapkey.Server{
		Signer:   signer,
		PinEntry: pinentry.New(),
		Logger:   log.Default(),
	}

	err = s.Run(context.Background())
	if err != nil {
		panic(err)
	}
}
