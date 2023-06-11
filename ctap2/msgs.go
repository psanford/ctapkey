package ctap2

type getInfoResponse struct {
	Versions                    []string                         `cbor:"1,keyasint"`
	Extensions                  []string                         `cbor:"2,keyasint,omitempty"`
	AAGUID                      [16]byte                         `cbor:"3,keyasint"`
	Options                     getInfoOptions                   `cbor:"4,keyasint,omitempty"`
	MaxMsgSize                  uint64                           `cbor:"5,keyasint,omitempty"`
	UVAuthProtocols             []uint64                         `cbor:"6,keyasint,omitempty"`
	MaxCredCountInList          uint64                           `cbor:"7,keyasint,omitempty"`
	MaxCredIdLen                uint64                           `cbor:"8,keyasint,omitempty"`
	Transports                  []string                         `cbor:"9,keyasint,omitempty"`
	Algorithms                  []publicKeyCrendentialParameters `cbor:"10,keyasint,omitempty"`
	MaxSerializedLargeBlobArray uint64                           `cbor:"11,keyasint,omitempty"`
	ForcePINChange              *bool                            `cbor:"12,keyasint,omitempty"`
	MinPINLength                uint64                           `cbor:"13,keyasint,omitempty"`
	FirmwareVersion             uint64                           `cbor:"14,keyasint,omitempty"`
}

type publicKeyCrendentialParameters struct {
	Alg  int    `cbor:"alg"`
	Type string `cbor:"type"`
}

type getInfoOptions struct {
	// Support resident keys aka discoverable credentials
	ResidentKey bool `cbor:"rk,omitempty"`

	// indicates if this is a platform authenticator. Platform authenticators
	// are non-removable, so a TPM implementation would be a platform authenticator
	// while a usb key is not
	Platform bool `cbor:"plat"`

	// ClientPin indicates if authenticator can accept a client pin.
	// Per fido-client-to-authenticator-protocol-v2.1-rd-20201208.html 6.4:
	// If present and set to true, it indicates that the device is capable of accepting a PIN from the client and PIN has been set.
	// If present and set to false, it indicates that the device is capable of accepting a PIN from the client and PIN has not been set yet.
	// If absent, it indicates that the device is not capable of accepting a PIN from the client.
	ClientPin *bool `cbor:"clientPin"`

	UserPresence     bool `cbor:"up,omitempty"`
	UserVerification bool `cbor:"uv,omitempty"`
}
