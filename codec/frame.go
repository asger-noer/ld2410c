// Package codec implements the LD2410C serial protocol: frame framing, command
// construction, and response parsing.
//
// It deliberately imports nothing from machine or any other hardware package so
// the wire format can be exercised by ordinary host tests. The hardware binding
// lives in the parent ld2410c package.
//
// The module speaks two frame types, distinguished by their header:
//
//	report frames  F4 F3 F2 F1 | len[2]LE | data[len] | F8 F7 F6 F5
//	config frames  FD FC FB FA | len[2]LE | data[len] | 04 03 02 01
//
// Report frames stream continuously at roughly 10 Hz. Config frames carry
// commands towards the module and ACKs back from it, and may be interleaved with
// report frames at any time, so a reader must be able to tell them apart rather
// than assume alignment.
package codec

import "errors"

// Frame delimiters.
var (
	ReportHeader = [4]byte{0xF4, 0xF3, 0xF2, 0xF1}
	ReportTail   = [4]byte{0xF8, 0xF7, 0xF6, 0xF5}
	ConfigHeader = [4]byte{0xFD, 0xFC, 0xFB, 0xFA}
	ConfigTail   = [4]byte{0x04, 0x03, 0x02, 0x01}
)

// Command words understood by the module. The protocol transmits these as
// 16-bit little-endian values; the high byte is always zero for a request and
// is set to 0x01 by the module in the corresponding ACK.
const (
	CmdEnableConfig       uint16 = 0x00FF // enter configuration mode
	CmdEndConfig          uint16 = 0x00FE // leave configuration mode
	CmdSetMaxDistance     uint16 = 0x0060 // max gates + unoccupied duration
	CmdReadParameters     uint16 = 0x0061 // read current configuration
	CmdEnableEngMode      uint16 = 0x0062 // per-gate energy reporting on
	CmdDisableEngMode     uint16 = 0x0063 // per-gate energy reporting off
	CmdSetGateSensitivity uint16 = 0x0064 // per-gate detection thresholds
	CmdReadFirmware       uint16 = 0x00A0 // firmware version
	CmdFactoryReset       uint16 = 0x00A2 // restore defaults
	CmdRestartModule      uint16 = 0x00A3 // reboot

	// Background noise calibration. The module measures the per-gate noise
	// floor over the requested window and derives its own sensitivities from
	// it, which is the same procedure the vendor's PC tool performs.
	CmdStartNoiseDetection uint16 = 0x000B // begin, value is duration in seconds
	CmdQueryNoiseDetection uint16 = 0x001B // poll progress
)

// Gates is the number of distance gates the module reports sensitivities for,
// numbered 0 through 8.
const Gates = 9

// MaxGate is the highest gate index, and MinConfigurableGate the lowest value
// accepted for the maximum-distance parameters of CmdSetMaxDistance, whose
// documented range is 2 to 8.
const (
	MaxGate             uint8 = Gates - 1
	MinConfigurableGate uint8 = 2
)

// Gate depth in centimetres. The module's distance resolution is selectable
// between 0.75 m and 0.2 m per gate; 0.75 m is the factory default and the only
// one this package configures, but helpers take the width explicitly so nothing
// silently assumes it.
const (
	GateWidthCM     uint16 = 75 // 0.75 m per gate, factory default
	GateWidthFineCM uint16 = 20 // 0.2 m per gate
)

// Report frame data types, carried in the first payload byte.
const (
	FrameTypeEngineering byte = 0x01
	FrameTypeBasic       byte = 0x02
)

// reportHeadMarker precedes the target data in both basic and engineering
// frames. The frame type, not this marker, is what distinguishes the two.
const reportHeadMarker byte = 0xAA

// MaxDataLen bounds the data payload the scanner will accept. Basic report
// frames carry 13 bytes and the largest ACK (read parameters) carries under 32;
// engineering-mode frames are the largest at roughly 45. 128 leaves headroom
// while keeping the scanner's copy buffer small enough for a microcontroller.
const MaxDataLen = 128

// Errors returned when a payload does not match the expected shape. Callers
// generally treat all of these as "resynchronise and try the next frame".
var (
	ErrShortPayload   = errors.New("ld2410c: payload too short")
	ErrHeadMarker     = errors.New("ld2410c: report missing 0xAA head marker")
	ErrFrameType      = errors.New("ld2410c: unrecognised report frame type")
	ErrACKCommand     = errors.New("ld2410c: ACK command word mismatch")
	ErrACKStatus      = errors.New("ld2410c: ACK reported failure status")
	ErrParamsMarker   = errors.New("ld2410c: parameters payload missing 0xAA marker")
	ErrSensitivity    = errors.New("ld2410c: sensitivity must be in range 0-100")
	ErrGateOutOfRange = errors.New("ld2410c: gate out of range")
)

// TargetState is the byte the module uses to describe the current detection.
//
// Values 0x00 to 0x03 are presence results whose low two bits are independent
// flags, so 0x03 means a moving and a stationary target are both present.
// Values 0x04 to 0x06 are status codes emitted only while background noise
// calibration is running. They share the same byte but are not bit flags, which
// matters: read naively, 0x05 has bit 0 set and would masquerade as a moving
// target, and 0x06 as a stationary one.
type TargetState uint8

const (
	TargetNone       TargetState = 0x00
	TargetMoving     TargetState = 0x01
	TargetStationary TargetState = 0x02
	TargetPresence   TargetState = 0x03 // moving and stationary simultaneously

	TargetNoiseDetecting TargetState = 0x04 // calibration in progress
	TargetNoiseSucceeded TargetState = 0x05 // calibration finished successfully
	TargetNoiseFailed    TargetState = 0x06 // calibration failed
)

// IsPresence reports whether the value describes a detection result rather than
// a calibration status code.
func (s TargetState) IsPresence() bool { return s <= TargetPresence }

// IsCalibration reports whether the value is a background noise calibration
// status code.
func (s TargetState) IsCalibration() bool {
	return s >= TargetNoiseDetecting && s <= TargetNoiseFailed
}

// HasMoving reports whether a moving target is present.
func (s TargetState) HasMoving() bool { return s.IsPresence() && s&TargetMoving != 0 }

// HasStationary reports whether a stationary target is present.
func (s TargetState) HasStationary() bool { return s.IsPresence() && s&TargetStationary != 0 }

// Detected reports whether the module sees a target of any kind. Calibration
// status codes are not detections.
func (s TargetState) Detected() bool { return s.IsPresence() && s != TargetNone }

func (s TargetState) String() string {
	switch s {
	case TargetMoving:
		return "moving"
	case TargetStationary:
		return "stationary"
	case TargetPresence:
		return "moving+stationary"
	case TargetNoiseDetecting:
		return "calibrating"
	case TargetNoiseSucceeded:
		return "calibration-succeeded"
	case TargetNoiseFailed:
		return "calibration-failed"
	default:
		return "none"
	}
}

// Frame holds the fields of one decoded basic report.
//
// It carries no timestamp: the module does not supply one, and stamping is the
// caller's responsibility so that the decoder stays free of a clock dependency.
type Frame struct {
	// Target classifies what the module currently sees.
	Target TargetState
	// MovingDistance is the range to the nearest moving target, in cm.
	// Only meaningful when Target.HasMoving.
	MovingDistance uint16
	// MovingEnergy is the moving target's signal strength, 0–100.
	MovingEnergy uint8
	// StationaryDistance is the range to the nearest stationary target, in cm.
	// Only meaningful when Target.HasStationary.
	StationaryDistance uint16
	// StationaryEnergy is the stationary target's signal strength, 0–100.
	StationaryEnergy uint8
	// DetectionDistance is the module's own combined range estimate to the
	// nearest target of any kind, in cm.
	DetectionDistance uint16
	// Engineering is true when the frame also carried per-gate energy values.
	// Those extra fields are not decoded here; the flag exists so a caller can
	// notice the module is in a mode it did not ask for.
	Engineering bool
}

// Parameters is the module's current configuration, as reported by
// CmdReadParameters.
type Parameters struct {
	MaxDistanceGate           uint8
	MaxMovingDistanceGate     uint8
	MaxStationaryDistanceGate uint8
	MovingSensitivity         [Gates]uint8
	StationarySensitivity     [Gates]uint8
	UnoccupiedDuration        uint16 // seconds
}

// ParseReport decodes the data payload of a report frame. The payload excludes
// the header, length, and tail, which Scanner has already validated.
//
// Payload layout:
//
//	[0]     frame type: 0x02 basic, 0x01 engineering
//	[1]     head marker, always 0xAA
//	[2]     target state
//	[3:5]   moving distance, cm, little-endian
//	[5]     moving energy
//	[6:8]   stationary distance, cm, little-endian
//	[8]     stationary energy
//	[9:11]  detection distance, cm, little-endian
//	[11:13] trailing markers 0x55 0x00
//
// Engineering frames carry the same basic fields at the same offsets and append
// per-gate energies afterwards, so both types decode identically here and the
// mode is recorded on the Frame rather than rejected.
//
// Note that the discriminator is the frame type at [0], not the head marker at
// [1]: the marker is 0xAA in both modes.
func ParseReport(data []byte) (Frame, error) {
	if len(data) < 11 {
		return Frame{}, ErrShortPayload
	}
	if data[0] != FrameTypeBasic && data[0] != FrameTypeEngineering {
		return Frame{}, ErrFrameType
	}
	if data[1] != reportHeadMarker {
		return Frame{}, ErrHeadMarker
	}
	return Frame{
		Target:             TargetState(data[2]),
		MovingDistance:     le16(data[3:]),
		MovingEnergy:       data[5],
		StationaryDistance: le16(data[6:]),
		StationaryEnergy:   data[8],
		DetectionDistance:  le16(data[9:]),
		Engineering:        data[0] == FrameTypeEngineering,
	}, nil
}

// ParseACK verifies that a config-frame payload is a successful acknowledgement
// of cmd.
//
// The module echoes the command word with the high byte set to 0x01, followed by
// a 16-bit status word where zero means success.
func ParseACK(data []byte, cmd uint16) error {
	if len(data) < 4 {
		return ErrShortPayload
	}
	if le16(data) != ackWord(cmd) {
		return ErrACKCommand
	}
	if le16(data[2:]) != 0 {
		return ErrACKStatus
	}
	return nil
}

// ackWord returns the command word the module echoes when acknowledging cmd.
func ackWord(cmd uint16) uint16 {
	return (cmd & 0x00FF) | ((cmd>>8 | 0x01) << 8)
}

// ParseParameters decodes the payload of a CmdReadParameters ACK.
//
// Payload layout after the four ACK bytes:
//
//	[4]  0xAA marker
//	[5]  maximum supported distance gate
//	[6]  configured maximum moving gate
//	[7]  configured maximum stationary gate
//	[8:] moving sensitivities, then stationary sensitivities, one byte per gate
//	     up to and including MaxDistanceGate, then the unoccupied duration as a
//	     16-bit little-endian value
//
// The sensitivity blocks are sized by the module's reported MaxDistanceGate
// rather than a fixed nine, so the offsets are computed rather than hardcoded.
func ParseParameters(data []byte) (Parameters, error) {
	if err := ParseACK(data, CmdReadParameters); err != nil {
		return Parameters{}, err
	}
	if len(data) < 8 {
		return Parameters{}, ErrShortPayload
	}
	if data[4] != 0xAA {
		return Parameters{}, ErrParamsMarker
	}

	p := Parameters{
		MaxDistanceGate:           data[5],
		MaxMovingDistanceGate:     data[6],
		MaxStationaryDistanceGate: data[7],
	}

	// The module can in principle report a larger gate count than we have room
	// for; clamp so a malformed reply cannot drive an out-of-range write.
	count := int(p.MaxDistanceGate) + 1
	if count > Gates {
		count = Gates
	}

	const movingOffset = 8
	stationaryOffset := movingOffset + count
	durationOffset := stationaryOffset + count
	if len(data) < durationOffset+2 {
		return Parameters{}, ErrShortPayload
	}

	for i := range count {
		p.MovingSensitivity[i] = data[movingOffset+i]
		p.StationarySensitivity[i] = data[stationaryOffset+i]
	}
	p.UnoccupiedDuration = le16(data[durationOffset:])

	return p, nil
}

func le16(b []byte) uint16 {
	return uint16(b[0]) | uint16(b[1])<<8
}
