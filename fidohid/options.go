package fidohid

type ctap2DisabledOption struct {
}

func (o *ctap2DisabledOption) setValue(k *SoftToken) {
	k.ctap2 = false
}

// Disable CTAP2 events and report that it is not supported.
// You must disable CTAP2 if you are not going to handle
// CTAP2 events, otherwise browsers won't fallback to U2F
// compatibility mode.
func WithCTAP2Disabled() Option {
	return &ctap2DisabledOption{}
}

type Option interface {
	setValue(*SoftToken)
}
