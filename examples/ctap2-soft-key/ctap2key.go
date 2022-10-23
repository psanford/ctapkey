package main

import (
	"context"
	"log"

	"github.com/psanford/ctapkey"
	"github.com/psanford/ctapkey/examples/ctap2-soft-key/ctap2memory"
	"github.com/psanford/ctapkey/pinentry"
)

func main() {
	signer, err := ctap2memory.New()
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
