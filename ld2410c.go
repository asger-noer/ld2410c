// Package ld2410c drives the HLK-LD2410C 24 GHz mmWave presence sensor over
// UART. The UART and OUT pin are abstracted behind the UART and InputPin
// interfaces so the package compiles and is testable on any host.
//
// All framing, command construction, and response parsing lives in the codec
// subpackage, which imports no hardware and is covered by host tests. This
// package is deliberately thin: it owns the UART, the read loop, and the
// concurrency, and nothing else.
package ld2410c

import (
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/asger-noer/ld2410c/codec"
)

// UART is the serial transport required by Device. *machine.UART satisfies
// this interface on TinyGo targets.
type UART interface {
	Buffered() int
	Read(p []byte) (int, error)
	Write(p []byte) (int, error)
}

// InputPin is the module's OUT pin, used for diagnostics. machine.Pin
// satisfies this interface on TinyGo targets.
type InputPin interface {
	Get() bool
}

// Baud is the module's factory-default serial speed.
const Baud = 256000

const (
	// readChunk bounds one bulk UART read. At 256000 baud the module emits
	// roughly 230 bytes per second in basic mode, so this drains comfortably
	// more than ever accumulates between polls.
	readChunk = 256

	// scanBuf must hold one maximum-size frame plus slack for a partial frame
	// straddling a read boundary.
	scanBuf = codec.MaxDataLen + 128

	// idlePoll is how long the read loop sleeps when the UART had nothing. It
	// yields to the network loop, which shares this core cooperatively.
	idlePoll = 5 * time.Millisecond

	// ackPoll and ackTimeout bound the wait for a command acknowledgement.
	//
	// The timeout is an overall deadline rather than a per-byte one. The previous
	// implementation allowed 200 ms per byte across a 256-byte scan, so a mute
	// module could stall the caller for close to a minute.
	ackPoll    = 2 * time.Millisecond
	ackTimeout = 500 * time.Millisecond

	// writeSettle is a pause after each command the module persists to flash.
	//
	// The range and sensitivity commands survive power loss, so applying one
	// involves a flash write. Issuing the next command while that is in progress
	// is the most likely explanation for the module answering a read-back with a
	// failure status immediately after a run of sensitivity writes, which is
	// what a single uninterrupted session produced in practice.
	writeSettle = 50 * time.Millisecond

	// muteTimeout is how long the read loop tolerates a silent module before
	// trying to unstick it, and recoverInterval the minimum gap between the
	// commands it sends to do so.
	//
	// muteTimeout is well inside a caller's liveness budget so recovery gets a
	// chance before a watchdog gives up, and comfortably longer than the
	// module's ~100 ms reporting period.
	muteTimeout     = 2 * time.Second
	recoverInterval = 3 * time.Second
)

// ErrACKTimeout is returned when the module does not acknowledge a command
// within ackTimeout.
var ErrACKTimeout = errors.New("ld2410c: timed out waiting for ACK")

// unoccupiedFallback is the hold time used when the module declines a zero one.
// Short enough that the caller's own hysteresis still dominates.
const unoccupiedFallback uint16 = 1

// TargetState and Parameters are the codec's types, re-exported so callers need
// not import both packages.
type (
	TargetState = codec.TargetState
	Parameters  = codec.Parameters
)

// GateSensitivity holds the minimum signal energy required for a detection to be
// reported at one distance gate, in the range 0–100.
//
// These are the module's own per-gate thresholds, and they are the primary noise
// rejection mechanism: because they are applied per gate, they account for
// signal strength falling off with distance in a way a single global floor
// cannot.
type GateSensitivity struct {
	Moving     uint8 // "red" values in the vendor's configuration tool
	Stationary uint8 // "blue" values in the vendor's configuration tool
}

// NoiseBasedThresholds contains per-gate thresholds derived from a bottom-noise
// calibration run in the vendor's configuration tool. Each threshold is the
// observed maximum noise floor plus a ten-point margin, capped at 100.
//
// The module can perform this calibration itself; see codec.CmdStartNoiseDetection.
var NoiseBasedThresholds = [codec.Gates]GateSensitivity{
	0: {Moving: 31, Stationary: 10},
	1: {Moving: 22, Stationary: 10},
	2: {Moving: 17, Stationary: 13},
	3: {Moving: 16, Stationary: 13},
	4: {Moving: 16, Stationary: 12},
	5: {Moving: 13, Stationary: 12},
	6: {Moving: 16, Stationary: 12},
	7: {Moving: 18, Stationary: 12},
	8: {Moving: 15, Stationary: 12},
}

// Stats are the device's diagnostic counters. A climbing ParseErrors or
// Discarded count points at wiring noise or a mismatched baud rate; a climbing
// Dropped count means the frame consumer is not keeping up; a climbing
// Recoveries count means the module keeps falling silent.
type Stats struct {
	Frames      uint32
	ParseErrors uint32
	Dropped     uint32
	Discarded   uint32
	Overruns    uint32
	Recoveries  uint32
}

// frameQueue is how many decoded frames may sit unread.
//
// The module reports at roughly 10 Hz, so this buffers about three seconds. The
// consumer is expected to be a tight loop that does no I/O; the buffer exists to
// absorb scheduler jitter, not a genuinely slow reader.
const frameQueue = 32

// Device is a connected LD2410C module.
//
// The mutex guards the UART and the scanner. Run acquires it once per bulk read
// rather than holding it across the whole loop, which lets a configuration
// session take it and keep exclusive ownership for the duration of an
// enable/command/disable exchange. Without that exclusivity the read loop would
// consume the ACK bytes the session is waiting for.
type Device struct {
	mu      sync.Mutex
	uart    UART
	scanner codec.Scanner
	readBuf [readChunk]byte
	cmdBuf  []byte

	// latest is the most recently decoded frame, and latestAt when it arrived.
	latest   codec.Frame
	latestAt time.Time

	// runStart is when the read loop began, and lastCommand when a command was
	// last written. Together with latestAt they tell the read loop whether the
	// module has genuinely gone silent or has merely not spoken since we last
	// interrupted it.
	runStart    time.Time
	lastCommand time.Time

	outPin InputPin
	frames chan codec.Frame

	logger *slog.Logger

	stats Stats
}

// SetLogger replaces the device's logger.
func (d *Device) SetLogger(logger *slog.Logger) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if logger != nil {
		d.logger = logger
	}
}

// Frames returns the stream of decoded measurements, at roughly 10 Hz.
//
// The consumer should be a loop that does no blocking I/O. If the queue fills,
// the oldest frame is dropped so the reader stays current.
func (d *Device) Frames() <-chan codec.Frame { return d.frames }

// OutPinHigh reports the module's own presence output. Provided for diagnostics;
// the frame stream is the authoritative source.
func (d *Device) OutPinHigh() bool { return d.outPin.Get() }

// Latest returns the most recently decoded frame and when it arrived. The zero
// time means nothing has been decoded yet.
func (d *Device) Latest() (codec.Frame, time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.latest, d.latestAt
}

// Stats returns the device's diagnostic counters.
func (d *Device) Stats() Stats {
	d.mu.Lock()
	defer d.mu.Unlock()
	s := d.stats
	s.Discarded = d.scanner.Discarded()
	s.Overruns = d.scanner.Overruns()
	return s
}

// Run continuously reads the UART and publishes decoded report frames. It must
// be called in its own goroutine and does not return.
//
// Decoding runs continuously rather than on demand. Reading in bulk keeps the
// decoder always current and yields the steady sample stream the presence state
// machine needs.
//
// Start it before configuring the module rather than after. The UART's receive
// buffer holds a fraction of a second at this baud rate, so leaving the module
// streaming into a buffer nobody drains loses bytes and hands the next
// configuration session a backlog of stale ones.
func (d *Device) Run() {
	d.mu.Lock()
	d.runStart = time.Now()
	d.mu.Unlock()

	for {
		if d.pump() {
			continue
		}
		d.recoverIfSilent()
		time.Sleep(idlePoll)
	}
}

// recoverIfSilent asks a module that has stopped reporting to leave
// configuration mode.
//
// A module in configuration mode emits no report frames, and it does not come
// out of that state on its own. Nor does resetting the host help: the module is
// separately powered and keeps its state, so a watchdog reboot leaves it exactly
// as silent as it was. Recovery has to be a command, and this is the only place
// that notices the silence.
//
// A module we have just spoken to is left alone. It is either mid-session, where
// silence is expected, or has only just been released, where it needs a moment.
func (d *Device) recoverIfSilent() {
	d.mu.Lock()
	defer d.mu.Unlock()

	silentSince := d.latestAt
	if silentSince.IsZero() {
		// Nothing has ever arrived, so measure from when we started listening.
		silentSince = d.runStart
	}

	now := time.Now()
	if now.Sub(silentSince) < muteTimeout || now.Sub(d.lastCommand) < recoverInterval {
		return
	}

	d.stats.Recoveries++
	d.logger.Warn("module silent, asking it to leave configuration mode",
		"silent_for", now.Sub(silentSince), "recoveries", d.stats.Recoveries)

	// endConfig records the write, so a failure here cannot spin: the next
	// attempt is gated on recoverInterval regardless of the outcome.
	if err := d.endConfig(); err != nil {
		d.logger.Debug("recovery command failed", "error", err)
	}
}

// pump reads whatever the UART has buffered and decodes any complete frames,
// reporting whether it made progress.
func (d *Device) pump() bool {
	d.mu.Lock()
	defer d.mu.Unlock()

	if n := d.fill(); n == 0 {
		return false
	}

	return d.decodeBuffered()
}

// fill moves buffered UART bytes into the scanner. Caller must hold mu.
func (d *Device) fill() int {
	if d.uart.Buffered() == 0 {
		return 0
	}
	n, err := d.uart.Read(d.readBuf[:])
	if err != nil {
		d.logger.Debug("uart read", "error", err)
	}
	if n > 0 {
		d.scanner.Write(d.readBuf[:n]) //nolint:errcheck // Write cannot fail
	}
	return n
}

// decodeBuffered drains every complete frame the scanner holds, publishing report
// frames. Caller must hold mu.
//
// Config frames are skipped: the module may emit a late or duplicate ACK at any
// time, and outside a configuration session there is nobody waiting for it.
func (d *Device) decodeBuffered() bool {
	progressed := false
	for {
		kind, data, ok := d.scanner.Next()
		if !ok {
			return progressed
		}
		progressed = true
		if kind != codec.KindReport {
			continue
		}
		f, err := codec.ParseReport(data)
		if err != nil {
			d.stats.ParseErrors++
			d.logger.Debug("discarding malformed report", "error", err)
			continue
		}
		d.record(f)
		d.publish(f)
	}
}

// record stores f as the latest measurement. Caller must hold mu.
func (d *Device) record(f codec.Frame) {
	if f.Engineering {
		// We never enable engineering mode, so this means the module is not in
		// the state we believe. The basic fields are still valid.
		d.logger.Warn("module is in engineering mode")
	}
	d.stats.Frames++
	d.latest = f
	d.latestAt = time.Now()
}

// publish offers f to the frame consumer, evicting the oldest queued frame if
// the queue is full.
func (d *Device) publish(f codec.Frame) {
	select {
	case d.frames <- f:
		return
	default:
	}

	d.stats.Dropped++
	select {
	case <-d.frames:
	default:
	}
	select {
	case d.frames <- f:
	default:
	}
}

// Config is the module configuration applied by Configure.
type Config struct {
	// Thresholds are the per-gate detection sensitivities. Gates 0 and 1 are
	// near-field fixed zones whose stationary threshold the module does not
	// accept, so only gates 2 and above are written.
	Thresholds [codec.Gates]GateSensitivity

	// MaxDistanceCM bounds detection range, rounded up to a whole gate. This is
	// the most useful control to narrow once a room has been measured, since
	// mmWave sees through a plasterboard wall into whatever is behind it.
	MaxDistanceCM uint16

	// GateWidthCM is the module's distance resolution. Leave zero for the
	// factory default of 75 cm per gate.
	GateWidthCM uint16

	// UnoccupiedDuration is how long the module keeps reporting a target after
	// it stops seeing one, in seconds.
	//
	// Zero asks for the module's instantaneous verdict, which is what the
	// presence state machine wants: it owns the hysteresis, and a hold time here
	// would nest inside its exit delay and add hidden latency to every
	// transition.
	UnoccupiedDuration uint16
}

// DefaultConfig returns the configuration used in production.
//
// MaxDistanceCM spans the module's full gate range, so range limiting is off
// until a specific room is measured, and the hold time is zero so hysteresis
// lives in exactly one place.
func DefaultConfig() Config {
	return Config{
		Thresholds:         NoiseBasedThresholds,
		MaxDistanceCM:      uint16(codec.Gates) * codec.GateWidthCM,
		GateWidthCM:        codec.GateWidthCM,
		UnoccupiedDuration: 0,
	}
}

func (c Config) gateWidth() uint16 {
	if c.GateWidthCM == 0 {
		return codec.GateWidthCM
	}
	return c.GateWidthCM
}

// Configure applies cfg to the module and verifies that it took effect.
//
// Every command is issued inside one configuration session. The previous
// implementation entered and left configuration mode once per gate, which cost
// seven enable/disable round trips plus fixed sleeps and let the module resume
// reporting between writes.
//
// The session reads before it writes and skips values that already match, so a
// sensor that has been configured once does not rewrite the module's flash on
// every boot. What is written is then read back, because an ACK only confirms
// the command was received and not that the value was kept. Mismatches are
// logged rather than returned: a value the module declines will be declined
// again, so failing here would only drive a caller's retry loop for no benefit.
func (d *Device) Configure(cfg Config) error {
	maxGate := codec.GateForDistanceCM(cfg.MaxDistanceCM, cfg.gateWidth())

	params, err := d.apply(cfg, maxGate, cfg.UnoccupiedDuration)
	if err != nil {
		return err
	}

	// The datasheet gives the hold time a range of 0 to 65535 but does not
	// confirm that 0 is honoured, and reading it back is the only way to find
	// out. If the module quietly kept something else, retry with a short hold.
	if cfg.UnoccupiedDuration == 0 && params.UnoccupiedDuration != 0 {
		d.logger.Warn("module declined a zero hold time, retrying with fallback",
			"reported_s", params.UnoccupiedDuration, "fallback_s", unoccupiedFallback)
		if params, err = d.apply(cfg, maxGate, unoccupiedFallback); err != nil {
			return err
		}
	}

	d.checkApplied(cfg, maxGate, params)
	return nil
}

// apply writes the whole configuration in one session and reads it back.
//
// The module's current configuration is read first, and only values that differ
// are written. Both the range and the sensitivity commands are persisted to the
// module's flash, so on an already-provisioned sensor this turns a boot that
// rewrote eight parameters into one that writes none: it keeps the session short
// and stops every reboot from costing flash write cycles.
func (d *Device) apply(cfg Config, maxGate uint8, unoccupied uint16) (Parameters, error) {
	var params Parameters

	err := d.session(func() error {
		current, err := d.readParameters()
		if err != nil {
			// Fall back to writing everything. Skipping the write because the
			// read failed would leave the module unconfigured on the strength of
			// a failure that says nothing about whether writes would work.
			d.logger.Warn("could not read current parameters, writing every value",
				"error", err)
			current = Parameters{}
		}

		wrote, err := d.writeChanged(cfg, maxGate, unoccupied, current)
		if err != nil {
			return err
		}
		if !wrote {
			params = current
			return nil
		}

		params, err = d.readParameters()
		return err
	})

	return params, err
}

// writeChanged writes the range, hold time, and per-gate thresholds that differ
// from current, reporting whether it wrote anything at all. Caller must hold mu
// and be inside a configuration session.
func (d *Device) writeChanged(cfg Config, maxGate uint8, unoccupied uint16, current Parameters) (bool, error) {
	wrote := false

	// Range and hold time first: they bound which gates matter. All three live
	// in one command, so it is written unless every part of it already matches.
	if current.MaxMovingDistanceGate != maxGate ||
		current.MaxStationaryDistanceGate != maxGate ||
		current.UnoccupiedDuration != unoccupied {
		if err := d.command(codec.CmdSetMaxDistance, func(dst []byte) ([]byte, error) {
			return codec.AppendSetMaxDistanceAndDuration(dst, maxGate, maxGate, unoccupied)
		}); err != nil {
			return wrote, fmt.Errorf("setting max distance and hold time: %w", err)
		}
		wrote = true
		time.Sleep(writeSettle)
	}

	for gate := int(codec.MinConfigurableGate); gate < len(cfg.Thresholds); gate++ {
		t := cfg.Thresholds[gate]
		if current.MovingSensitivity[gate] == t.Moving &&
			current.StationarySensitivity[gate] == t.Stationary {
			continue
		}
		if err := d.command(codec.CmdSetGateSensitivity, func(dst []byte) ([]byte, error) {
			return codec.AppendSetGateSensitivity(dst, uint16(gate), t.Moving, t.Stationary)
		}); err != nil {
			return wrote, fmt.Errorf("setting gate %d sensitivity: %w", gate, err)
		}
		wrote = true
		time.Sleep(writeSettle)
	}

	return wrote, nil
}

// checkApplied compares the module's reported configuration against what was
// requested, logging anything that did not stick.
func (d *Device) checkApplied(cfg Config, maxGate uint8, got Parameters) {
	mismatches := 0
	warn := func(field string, want, have any) {
		mismatches++
		d.logger.Warn("module configuration was not applied",
			"field", field, "requested", want, "reported", have)
	}

	if got.MaxMovingDistanceGate != maxGate {
		warn("max_moving_gate", maxGate, got.MaxMovingDistanceGate)
	}
	if got.MaxStationaryDistanceGate != maxGate {
		warn("max_stationary_gate", maxGate, got.MaxStationaryDistanceGate)
	}
	for gate := int(codec.MinConfigurableGate); gate < len(cfg.Thresholds); gate++ {
		if want := cfg.Thresholds[gate].Moving; got.MovingSensitivity[gate] != want {
			warn(fmt.Sprintf("gate_%d_moving", gate), want, got.MovingSensitivity[gate])
		}
		if want := cfg.Thresholds[gate].Stationary; got.StationarySensitivity[gate] != want {
			warn(fmt.Sprintf("gate_%d_stationary", gate), want, got.StationarySensitivity[gate])
		}
	}

	if mismatches > 0 {
		d.logger.Warn("module configuration only partially applied", "mismatches", mismatches)
		return
	}
	d.logger.Info(
		"module configured and verified",
		"max_gate", maxGate,
		"max_distance_cm", uint16(maxGate+1)*cfg.gateWidth(),
		"unoccupied_duration_s", got.UnoccupiedDuration,
	)
}

// SetGateSensitivity sets the detection thresholds for one distance gate.
func (d *Device) SetGateSensitivity(gate, moving, stationary uint8) error {
	return d.session(func() error {
		return d.command(codec.CmdSetGateSensitivity, func(dst []byte) ([]byte, error) {
			return codec.AppendSetGateSensitivity(dst, uint16(gate), moving, stationary)
		})
	})
}

// SetAllGateSensitivity sets the same thresholds for every distance gate.
func (d *Device) SetAllGateSensitivity(moving, stationary uint8) error {
	return d.session(func() error {
		return d.command(codec.CmdSetGateSensitivity, func(dst []byte) ([]byte, error) {
			return codec.AppendSetGateSensitivity(dst, codec.AllGates, moving, stationary)
		})
	})
}

// SetMaxDistanceAndDuration bounds detection range and sets the module's own
// presence hold time. Gates must be between codec.MinConfigurableGate and
// codec.MaxGate; unoccupiedDuration is in seconds.
func (d *Device) SetMaxDistanceAndDuration(maxMovingGate, maxStationaryGate uint8, unoccupiedDuration uint16) error {
	return d.session(func() error {
		return d.command(codec.CmdSetMaxDistance, func(dst []byte) ([]byte, error) {
			return codec.AppendSetMaxDistanceAndDuration(dst, maxMovingGate, maxStationaryGate, unoccupiedDuration)
		})
	})
}

// EnableEngineeringMode adds per-gate energy values to report frames.
func (d *Device) EnableEngineeringMode() error {
	return d.session(func() error { return d.simpleCommand(codec.CmdEnableEngMode) })
}

// DisableEngineeringMode returns the module to basic reports.
func (d *Device) DisableEngineeringMode() error {
	return d.session(func() error { return d.simpleCommand(codec.CmdDisableEngMode) })
}

// RestartModule reboots the module. It acknowledges before restarting, so expect
// several seconds of silence afterwards.
func (d *Device) RestartModule() error {
	return d.session(func() error { return d.simpleCommand(codec.CmdRestartModule) })
}

// FactoryReset restores defaults. A restart is required for them to take effect.
func (d *Device) FactoryReset() error {
	return d.session(func() error { return d.simpleCommand(codec.CmdFactoryReset) })
}

// ReadParameters retrieves the module's current configuration.
func (d *Device) ReadParameters() (Parameters, error) {
	var p Parameters
	err := d.session(func() error {
		var err error
		p, err = d.readParameters()
		return err
	})
	return p, err
}

// readParameters reads the module's configuration. Caller must hold mu and be
// inside a configuration session.
func (d *Device) readParameters() (Parameters, error) {
	data, err := d.exchange(codec.CmdReadParameters, codec.AppendReadParameters(d.cmdBuf[:0]))
	if err != nil {
		return Parameters{}, fmt.Errorf("reading parameters: %w", err)
	}
	return codec.ParseParameters(data)
}

// ReadFirmwareVersion reads the module's firmware version.
func (d *Device) ReadFirmwareVersion() (string, error) {
	var version string
	err := d.session(func() error {
		data, err := d.exchange(codec.CmdReadFirmware, codec.AppendReadFirmware(d.cmdBuf[:0]))
		if err != nil {
			return err
		}
		// Payload after the ACK: 2 bytes type, 2 bytes major, 4 bytes minor.
		if len(data) < 12 {
			return codec.ErrShortPayload
		}
		version = fmt.Sprintf("V%d.%02d.%02X%02X%02X%02X",
			data[7], data[6], data[11], data[10], data[9], data[8])
		return nil
	})
	return version, err
}

// session runs fn inside a configuration-mode session, holding the UART lock
// throughout.
//
// The lock spans the whole session rather than each command: the module ignores
// everything until configuration mode is entered, and the read loop would
// otherwise consume the ACK bytes fn is waiting for.
func (d *Device) session(fn func() error) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	err := d.enableConfig()
	if err != nil {
		err = fmt.Errorf("entering config mode: %w", err)
	} else {
		err = fn()
	}

	// Leaving configuration mode is attempted even when entering it appeared to
	// fail, which it did not used to be. A lost or late ACK for the enable
	// command is indistinguishable from the module ignoring it, and in the
	// former case the module is now in configuration mode and has stopped
	// reporting entirely. It stays powered across a host reset, so skipping this
	// silenced the radar until the sensor was unplugged: the watchdog rebooted
	// the board, the module kept its state, and the board rebooted again.
	if endErr := d.endConfig(); endErr != nil {
		err = errors.Join(err, fmt.Errorf("leaving config mode: %w", endErr))
	}
	return err
}

// enableConfig enters configuration mode, after which the module accepts
// commands and stops emitting report frames.
//
// The command carries the value 0x0001 the protocol requires. Sending it bare,
// as this used to, is out of spec and the module's response to it is not
// something the datasheet defines.
func (d *Device) enableConfig() error {
	return d.command(codec.CmdEnableConfig, func(dst []byte) ([]byte, error) {
		return codec.AppendEnableConfig(dst), nil
	})
}

// endConfig leaves configuration mode, after which the module resumes reporting.
func (d *Device) endConfig() error {
	return d.command(codec.CmdEndConfig, func(dst []byte) ([]byte, error) {
		return codec.AppendEndConfig(dst), nil
	})
}

// simpleCommand sends a command with no parameters and awaits its ACK.
func (d *Device) simpleCommand(cmd uint16) error {
	return d.command(cmd, func(dst []byte) ([]byte, error) {
		return codec.AppendCommand(dst, cmd), nil
	})
}

// command builds a frame with build, sends it, and awaits its ACK.
//
// build is invoked before anything is written, so a rejected argument cannot
// leave the module half-configured.
func (d *Device) command(cmd uint16, build func([]byte) ([]byte, error)) error {
	frame, err := build(d.cmdBuf[:0])
	if err != nil {
		return err
	}
	_, err = d.exchange(cmd, frame)
	return err
}

// exchange writes frame and waits for the matching ACK, returning its payload.
// Caller must hold mu.
//
// Report frames continue to arrive throughout, and the module may still emit a
// stale ACK for an earlier command, so this matches on the command word instead
// of trusting the next config frame to be the right one. A non-zero status is
// returned immediately rather than waited out.
func (d *Device) exchange(cmd uint16, frame []byte) ([]byte, error) {
	// Everything the module said before this command was written is stale.
	// Report frames are published, config frames are dropped: without this, a
	// late or duplicate ACK still sitting in the buffer can satisfy the wait
	// below and let the caller run ahead of the module, issuing its next command
	// before the module has finished the previous one.
	d.fill()
	d.decodeBuffered()

	if _, err := d.uart.Write(frame); err != nil {
		return nil, fmt.Errorf("writing command %#04x: %w", cmd, err)
	}
	d.lastCommand = time.Now()

	deadline := time.Now().Add(ackTimeout)
	for {
		d.fill()
		for {
			kind, data, ok := d.scanner.Next()
			if !ok {
				break
			}
			if kind == codec.KindReport {
				// Keep measurements flowing even while configuring, so the
				// presence state machine does not see a gap it would read as a
				// dead radar.
				if f, err := codec.ParseReport(data); err == nil {
					d.record(f)
					d.publish(f)
				}
				continue
			}
			switch err := codec.ParseACK(data, cmd); {
			case err == nil:
				return data, nil
			case errors.Is(err, codec.ErrACKCommand):
				continue // an ACK for some other command; keep waiting for ours
			default:
				return nil, fmt.Errorf("command %#04x: %w", cmd, err)
			}
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("command %#04x: %w", cmd, ErrACKTimeout)
		}
		time.Sleep(ackPoll)
	}
}
