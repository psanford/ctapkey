package ctap2

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

const (
	CmdMakeCredential   = 0x01
	CmdGetAssertion     = 0x02
	CmdGetInfo          = 0x04
	CmdClientPin        = 0x06
	CmdReset            = 0x07
	CmdGetNextAssertion = 0x08
)

type Fido2Signer interface {
	RegisterKey(applicationParam []byte) ([]byte, *big.Int, *big.Int, error)
	SignASN1(keyHandle, applicationParam, digest []byte) ([]byte, error)
	Counter() uint32
	// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	Fido2FooBar()
}

type CTAP2Key struct {
	Signer      Fido2Signer
	cborEncMode cbor.EncMode
}

func New(signer Fido2Signer) *CTAP2Key {
	em, _ := cbor.CTAP2EncOptions().EncMode()

	return &CTAP2Key{
		Signer:      signer,
		cborEncMode: em,
	}
}

func (c *CTAP2Key) HandleMsg(raw []byte) ([]byte, error) {
	msg, err := decodeMsg(raw)
	if err != nil {
		return nil, err
	}

	switch msg.Command {
	case CmdGetInfo:
		return c.handleGetInfo()
	}

	return nil, fmt.Errorf("unimplemented ctap2 cmd: %d", msg.Command)

}

func (c *CTAP2Key) handleGetInfo() ([]byte, error) {
	tf := true
	info := getInfoResponse{
		// leave out "FIDO_2_1" for now.
		// add back in when all features listed here are implemented:
		// https://fidoalliance.org/specs/fido-v2.1-rd-20201208/fido-client-to-authenticator-protocol-v2.1-rd-20201208.html#mandatory-features
		Versions: []string{"U2F_V2", "FIDO_2_0"},
		// Extensions: []string{"credProtect", "hmac-secret"},
		AAGUID: [16]byte([]byte("AAGUID0123456789")),
		Options: getInfoOptions{
			Platform:         false, // XXX this should probably be configurable
			ResidentKey:      true,
			UserPresence:     true,
			UserVerification: false,
			ClientPin:        &tf, // false will trigger prompt to set the pin, true will assume a pin is set.

		},
		MaxMsgSize:         1200,
		UVAuthProtocols:    []uint64{2, 1},
		MaxCredCountInList: 8,
		MaxCredIdLen:       128,
		Transports:         []string{"usb"},
		Algorithms: []publicKeyCrendentialParameters{
			{
				Alg:  -7,
				Type: "public-key",
			},
			{
				Alg:  -8,
				Type: "public-key",
			},
		},
		MinPINLength: 4,
	}

	msg, err := c.cborEncMode.Marshal(info)
	if err != nil {
		return nil, err
	}

	msg = c.encodeStatus(msg, CTAP1_ERR_SUCCESS)

	return msg, nil
}

func (c *CTAP2Key) encodeStatus(msg []byte, status uint8) []byte {
	out := make([]byte, len(msg)+1)
	out[0] = status
	copy(out[1:], msg)
	return out
}

type cmdMsg struct {
	Command uint8
	Data    []byte
}

func decodeMsg(raw []byte) (*cmdMsg, error) {
	if len(raw) < 1 {
		return nil, errors.New("cbor decode msg empty")
	}

	cmd := raw[0]

	msg := cmdMsg{
		Command: cmd,
		Data:    raw[1:],
	}

	return &msg, nil
}

// fido-client-to-authenticator-protocol-v2.1-rd-20201208 section 10.1
// In this current version of U2F, the framing is defined based on the ISO7816-4:2005 extended APDU format.
type ApduFrame struct {
	cla uint8 // class
	ins uint8 // instruction
	p1  uint8 // param1
	p2  uint8 // param2
}
