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
	Signer Fido2Signer
}

func New(signer Fido2Signer) *CTAP2Key {
	return &CTAP2Key{
		Signer: signer,
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
	info := getInfoResponse{
		Versions: []string{"FIDO_2_1", "FIDO_2_0", "U2F_V2"},
	}
	return cbor.Marshal(info)
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
