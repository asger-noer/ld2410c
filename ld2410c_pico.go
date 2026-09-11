//go:build rp2040 || rp2350

package ld2410c

import (
	"fmt"
	"log/slog"
	"machine"

	"github.com/asger-noer/ld2410c/codec"
)

// NewDevice configures the UART and OUT pin and returns a ready device. Call
// Run in its own goroutine to begin decoding.
//
// The OUT pin is configured as an input for diagnostics but is not used to
// drive anything. It carries the module's own one-bit presence verdict subject
// to the module's hold time, which the decoded frame stream supersedes in
// every respect.
func NewDevice(tx, rx, out machine.Pin, uart *machine.UART) (*Device, error) {
	if err := uart.Configure(machine.UARTConfig{
		BaudRate: Baud,
		TX:       tx,
		RX:       rx,
	}); err != nil {
		return nil, fmt.Errorf("ld2410c: configuring uart: %w", err)
	}
	out.Configure(machine.PinConfig{Mode: machine.PinInputPulldown})

	d := &Device{
		uart:   uart,
		outPin: out,
		frames: make(chan codec.Frame, frameQueue),
		cmdBuf: make([]byte, 0, 64),
		logger: slog.Default(),
	}
	if err := d.scanner.Reset(make([]byte, scanBuf)); err != nil {
		return nil, fmt.Errorf("ld2410c: %w", err)
	}

	return d, nil
}
