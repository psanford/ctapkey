package pinentry

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"time"

	assuan "github.com/foxcpp/go-assuan/client"
	"github.com/foxcpp/go-assuan/pinentry"
)

type request struct {
	timeout       time.Duration
	pendingResult chan Result
	extendTimeout chan time.Duration

	reqID []byte
}

type gpgPinentry struct {
	mu            sync.Mutex
	activeRequest *request
}

func New() PinEntry {
	return &gpgPinentry{}
}

func (pe *gpgPinentry) ConfirmPresence(prompt string, id []byte) (chan Result, error) {
	pe.mu.Lock()
	defer pe.mu.Unlock()

	timeout := 2 * time.Second

	if pe.activeRequest != nil {
		if !bytes.Equal(pe.activeRequest.reqID, id) {
			return nil, errors.New("other request already in progress")
		}

		extendTimeoutChan := pe.activeRequest.extendTimeout

		go func() {
			select {
			case extendTimeoutChan <- timeout:
			case <-time.After(timeout):
			}
		}()

		return pe.activeRequest.pendingResult, nil
	}

	pe.activeRequest = &request{
		timeout:       timeout,
		reqID:         id,
		pendingResult: make(chan Result),
		extendTimeout: make(chan time.Duration),
	}

	go pe.prompt(pe.activeRequest, prompt)

	return pe.activeRequest.pendingResult, nil
}

func (pe *gpgPinentry) GetPin(prompt string, id []byte) (chan Result, error) {
	return nil, errors.New("GetPin not implemented")
}

func (pe *gpgPinentry) prompt(req *request, prompt string) {
	sendResult := func(r Result) {
		select {
		case req.pendingResult <- r:
		case <-time.After(req.timeout):
			// we expect requests to come in every ~750ms.
			// If we've been waiting for 2 seconds the client
			// is likely gone.
		}

		pe.mu.Lock()
		pe.activeRequest = nil
		pe.mu.Unlock()
	}

	childCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	p, cmd, err := launchPinEntry(childCtx)
	if err != nil {
		sendResult(Result{
			OK:    false,
			Error: fmt.Errorf("failed to start pinentry: %w", err),
		})
		return
	}
	defer func() {
		cancel()
		cmd.Wait()
	}()

	defer p.Shutdown()
	p.SetTitle("TPM-FIDO")
	p.SetPrompt("TPM-FIDO")
	p.SetDesc(prompt)

	promptResult := make(chan bool)

	go func() {
		err := p.Confirm()
		promptResult <- err == nil
	}()

	timer := time.NewTimer(req.timeout)

	for {
		select {
		case ok := <-promptResult:
			sendResult(Result{
				OK: ok,
			})
			return
		case <-timer.C:
			sendResult(Result{
				OK:    false,
				Error: errors.New("request timed out"),
			})
			return
		case d := <-req.extendTimeout:
			if !timer.Stop() {
				<-timer.C
			}
			timer.Reset(d)
		}
	}
}

func launchPinEntry(ctx context.Context) (*pinentry.Client, *exec.Cmd, error) {
	cmd := exec.CommandContext(ctx, "pinentry")

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, nil, err
	}

	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}

	var c pinentry.Client
	c.Session, err = assuan.Init(assuan.ReadWriteCloser{
		ReadCloser:  stdout,
		WriteCloser: stdin,
	})

	if err != nil {
		return nil, nil, err
	}
	return &c, cmd, nil
}
