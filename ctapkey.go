package ctapkey

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"time"

	"github.com/psanford/ctapkey/attestation"
	"github.com/psanford/ctapkey/ctap2"
	"github.com/psanford/ctapkey/fidohid"
	"github.com/psanford/ctapkey/log"
	"github.com/psanford/ctapkey/pinentry"
	"github.com/psanford/ctapkey/sitesignatures"
	"github.com/psanford/ctapkey/statuscode"
	"github.com/psanford/ctapkey/u2f"
)

type Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
}

type Fido2Signer interface {
	Signer
	// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	Fido2FooBar()
}

type Server struct {
	PinEntry pinentry.PinEntry
	Signer   Signer
	UHidName string
	Logger   log.Logger
	ctap2    *ctap2.CTAP2Key
}

func (s *Server) Run(ctx context.Context) error {
	if s.Signer == nil {
		return errors.New("Signer cannot be nil")
	}
	if s.PinEntry == nil {
		return errors.New("PinEntry cannot be nil")
	}

	if s.Logger == nil {
		s.Logger = log.DefaultLogger
	}

	if s.UHidName == "" {
		s.UHidName = "ctapkey"
	}

	f2s, isFido2 := s.Signer.(Fido2Signer)

	var tokenOpts []fidohid.Option
	if isFido2 {
		s.ctap2 = ctap2.New(f2s)
	} else {
		tokenOpts = append(tokenOpts, fidohid.WithCTAP2Disabled())
	}

	token, err := fidohid.New(ctx, s.UHidName, tokenOpts...)
	if err != nil {
		return fmt.Errorf("create fido hid error: %w", err)
	}

	go token.Run(ctx)

	for evt := range token.Events() {
		s.Logger.Printf("got evt: %+v", evt)
		if evt.Error != nil {
			s.Logger.Printf("got token error: %s", err)
			continue
		}

		if evt.Cmd == fidohid.CmdCbor {
			// ctap2 messages are encapsulated in CmdCbor.
			respBytes, err := s.ctap2.HandleMsg(evt.Msg)
			if err != nil {
				s.Logger.Printf("fido2 err: %s, msg: %02x", err, evt.Msg)
				continue
			}

			// for cbor we don't set the status here. The status
			// is the first byte in the cbor part of the payload
			token.WriteResponse(ctx, evt, respBytes, 0)
			continue
		}

		req, err := u2f.DecodeAuthenticatorRequest(evt.Msg)
		if err != nil {
			s.Logger.Printf("decode u2f msg error: %s", err)
			continue
		}

		if req.Command == u2f.CmdAuthenticate {
			s.Logger.Printf("got AuthenticateCmd site=%s", sitesignatures.FromAppParam(req.Authenticate.ApplicationParam))

			s.handleAuthenticate(ctx, token, evt, req)
		} else if req.Command == u2f.CmdRegister {
			s.Logger.Printf("got RegisterCmd site=%s", sitesignatures.FromAppParam(req.Register.ApplicationParam))
			s.handleRegister(ctx, token, evt, req)
		} else if req.Command == u2f.CmdVersion {
			s.Logger.Printf("got VersionCmd")
			s.handleVersion(ctx, token, evt)
		} else {
			s.Logger.Printf("unsupported request type: 0x%02x\n", req.Command)
			// send a not supported error for any commands that we don't understand.
			// Browsers depend on this to detect what features the token supports
			// (i.e. the u2f backwards compatibility)

			token.WriteResponse(ctx, evt, nil, statuscode.ClaNotSupported)
		}
	}

	return ctx.Err()
}

func (s *Server) handleVersion(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.HIDEvent) {
	token.WriteResponse(parentCtx, evt, []byte("U2F_V2"), statuscode.NoError)
}

func (s *Server) handleAuthenticate(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.HIDEvent, req *u2f.AuthenticatorRequest) {
	keyHandle := req.Authenticate.KeyHandle
	appParam := req.Authenticate.ApplicationParam[:]

	dummySig := sha256.Sum256([]byte("meticulously-Bacardi"))

	_, err := s.Signer.SignASN1(keyHandle, appParam, dummySig[:])
	if err != nil {
		s.Logger.Printf("invalid key: %s (key handle size: %d)", err, len(keyHandle))

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			s.Logger.Printf("send bad key handle msg err: %s", err)
		}

		return
	}

	switch req.Authenticate.Ctrl {
	case u2f.CtrlCheckOnly,
		u2f.CtrlDontEnforeUserPresenceAndSign,
		u2f.CtrlEnforeUserPresenceAndSign:
	default:
		s.Logger.Printf("unknown authenticate control value: %d", req.Authenticate.Ctrl)

		err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
		if err != nil {
			s.Logger.Printf("send wrong-data msg err: %s", err)
		}
		return
	}

	if req.Authenticate.Ctrl == u2f.CtrlCheckOnly {
		// check if the provided key is known by the token
		s.Logger.Printf("check-only success")
		// test-of-user-presence-required: note that despite the name this signals a success condition
		err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			s.Logger.Printf("send bad key handle msg err: %s", err)
		}
		return
	}

	var userPresent uint8

	if req.Authenticate.Ctrl == u2f.CtrlEnforeUserPresenceAndSign {

		pinResultCh, err := s.PinEntry.ConfirmPresence("FIDO Confirm Auth", pinEntryID(req.Authenticate.ChallengeParam, req.Authenticate.ApplicationParam))

		if err != nil {
			s.Logger.Printf("pinentry err: %s", err)
			token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)

			return
		}

		childCtx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
		defer cancel()

		select {
		case result := <-pinResultCh:
			if result.OK {
				userPresent = 0x01
			} else {
				if result.Error != nil {
					s.Logger.Printf("Got pinentry result err: %s", result.Error)
				}

				// Got user cancelation, we want to propagate that so the browser gives up.
				// This isn't normally supported by a key so there's no status code for this.
				// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
				err := token.WriteResponse(parentCtx, evt, nil, statuscode.WrongData)
				if err != nil {
					s.Logger.Printf("Write WrongData resp err: %s", err)
				}
				return
			}
		case <-childCtx.Done():
			err := token.WriteResponse(parentCtx, evt, nil, statuscode.ConditionsNotSatisfied)
			if err != nil {
				s.Logger.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			}
			return
		}
	}

	signCounter := s.Signer.Counter()

	var toSign bytes.Buffer
	toSign.Write(req.Authenticate.ApplicationParam[:])
	toSign.WriteByte(userPresent)
	binary.Write(&toSign, binary.BigEndian, signCounter)
	toSign.Write(req.Authenticate.ChallengeParam[:])

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sig, err := s.Signer.SignASN1(keyHandle, appParam, sigHash.Sum(nil))
	if err != nil {
		s.Logger.Printf("auth sign err: %s", err)
	}

	var out bytes.Buffer
	out.WriteByte(userPresent)
	binary.Write(&out, binary.BigEndian, signCounter)
	out.Write(sig)

	err = token.WriteResponse(parentCtx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		s.Logger.Printf("write auth response err: %s", err)
		return
	}
}

func (s *Server) handleRegister(parentCtx context.Context, token *fidohid.SoftToken, evt fidohid.HIDEvent, req *u2f.AuthenticatorRequest) {
	ctx, cancel := context.WithTimeout(parentCtx, 750*time.Millisecond)
	defer cancel()

	pinResultCh, err := s.PinEntry.ConfirmPresence("FIDO Confirm Register", pinEntryID(req.Register.ChallengeParam, req.Register.ApplicationParam))

	if err != nil {
		s.Logger.Printf("pinentry err: %s", err)
		token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)

		return
	}

	select {
	case result := <-pinResultCh:
		if !result.OK {
			if result.Error != nil {
				s.Logger.Printf("Got pinentry result err: %s", result.Error)
			}

			// Got user cancelation, we want to propagate that so the browser gives up.
			// This isn't normally supported by a key so there's no status code for this.
			// WrongData seems like the least incorrect status code ¯\_(ツ)_/¯
			err := token.WriteResponse(ctx, evt, nil, statuscode.WrongData)
			if err != nil {
				s.Logger.Printf("Write WrongData resp err: %s", err)
				return
			}
			return
		}

		s.registerSite(parentCtx, token, evt, req)
	case <-ctx.Done():
		err := token.WriteResponse(ctx, evt, nil, statuscode.ConditionsNotSatisfied)
		if err != nil {
			s.Logger.Printf("Write swConditionsNotSatisfied resp err: %s", err)
			return
		}
	}
}

func (s *Server) registerSite(ctx context.Context, token *fidohid.SoftToken, evt fidohid.HIDEvent, req *u2f.AuthenticatorRequest) {
	keyHandle, x, y, err := s.Signer.RegisterKey(req.Register.ApplicationParam[:])
	if err != nil {
		s.Logger.Printf("RegisteKey err: %s", err)
		return
	}

	if len(keyHandle) > 255 {
		s.Logger.Printf("Error: keyHandle too large: %d, max=255", len(keyHandle))
		return
	}

	childPubKey := elliptic.Marshal(elliptic.P256(), x, y)

	var toSign bytes.Buffer
	toSign.WriteByte(0)
	toSign.Write(req.Register.ApplicationParam[:])
	toSign.Write(req.Register.ChallengeParam[:])
	toSign.Write(keyHandle)
	toSign.Write(childPubKey)

	sigHash := sha256.New()
	sigHash.Write(toSign.Bytes())

	sum := sigHash.Sum(nil)

	sig, err := ecdsa.SignASN1(rand.Reader, attestation.PrivateKey, sum)
	if err != nil {
		s.Logger.Printf("attestation sign err: %s", err)
		return
	}

	var out bytes.Buffer
	out.WriteByte(0x05) // reserved value
	out.Write(childPubKey)
	out.WriteByte(byte(len(keyHandle)))
	out.Write(keyHandle)
	out.Write(attestation.CertDer)
	out.Write(sig)

	err = token.WriteResponse(ctx, evt, out.Bytes(), statuscode.NoError)
	if err != nil {
		s.Logger.Printf("write register response err: %s", err)
		return
	}
}

func mustRand(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}

	return b
}

func pinEntryID(chalParam, appParam [32]byte) []byte {
	peID := make([]byte, len(chalParam), len(appParam))
	copy(peID, chalParam[:])
	copy(peID[len(chalParam):], appParam[:])

	return peID
}
