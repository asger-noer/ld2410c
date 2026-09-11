package codec

// This file builds outbound command frames. Every helper appends to dst and
// returns the extended slice, so a caller can reuse one scratch buffer across
// a whole configuration session and avoid allocating on the heap.
//
// All commands share the config framing:
//
//	FD FC FB FA | len[2]LE | cmd[2]LE | payload... | 04 03 02 01
//
// where len counts the command word plus payload. Parameter values are carried
// as 32-bit little-endian words, each preceded by a 16-bit parameter selector.

// AppendCommand frames cmd and payload as a config frame and appends it to dst.
func AppendCommand(dst []byte, cmd uint16, payload ...byte) []byte {
	dst = append(dst, ConfigHeader[:]...)
	dataLen := 2 + len(payload)
	dst = append(dst, byte(dataLen), byte(dataLen>>8))
	dst = append(dst, byte(cmd), byte(cmd>>8))
	dst = append(dst, payload...)
	return append(dst, ConfigTail[:]...)
}

// AppendEnableConfig appends the "enter configuration mode" command.
//
// The module ignores every other command until this succeeds, and stops emitting
// report frames until configuration mode is left again.
func AppendEnableConfig(dst []byte) []byte {
	return AppendCommand(dst, CmdEnableConfig, 0x01, 0x00)
}

// AppendEndConfig appends the "leave configuration mode" command, after which
// the module resumes streaming report frames.
func AppendEndConfig(dst []byte) []byte {
	return AppendCommand(dst, CmdEndConfig)
}

// AppendReadParameters appends the "read current configuration" command.
func AppendReadParameters(dst []byte) []byte {
	return AppendCommand(dst, CmdReadParameters)
}

// AppendReadFirmware appends the "read firmware version" command.
func AppendReadFirmware(dst []byte) []byte {
	return AppendCommand(dst, CmdReadFirmware)
}

// AppendEnableEngineeringMode appends the command that adds per-gate energy
// values to report frames.
func AppendEnableEngineeringMode(dst []byte) []byte {
	return AppendCommand(dst, CmdEnableEngMode)
}

// AppendDisableEngineeringMode appends the command that returns the module to
// basic reports.
func AppendDisableEngineeringMode(dst []byte) []byte {
	return AppendCommand(dst, CmdDisableEngMode)
}

// AppendRestartModule appends the reboot command.
func AppendRestartModule(dst []byte) []byte {
	return AppendCommand(dst, CmdRestartModule)
}

// AppendFactoryReset appends the "restore defaults" command. The module must be
// restarted for it to take effect.
func AppendFactoryReset(dst []byte) []byte {
	return AppendCommand(dst, CmdFactoryReset)
}

// AllGates selects every configurable gate at once in
// AppendSetGateSensitivity.
const AllGates uint16 = 0xFFFF

// AppendSetGateSensitivity appends a per-gate threshold command.
//
// Pass AllGates as gate to apply the same thresholds everywhere. moving and
// stationary are energy floors in the range 0–100: the module reports a target
// at that gate only when the measured energy exceeds the floor, so these are
// the primary noise rejection control. A floor of 100 disables the gate
// entirely, which is how a specific distance band is excluded.
//
// Gates 0 and 1 have no settable stationary threshold; the module accepts the
// command but ignores that field.
func AppendSetGateSensitivity(dst []byte, gate uint16, moving, stationary uint8) ([]byte, error) {
	if moving > 100 || stationary > 100 {
		return dst, ErrSensitivity
	}
	if gate != AllGates && gate >= Gates {
		return dst, ErrGateOutOfRange
	}
	return AppendCommand(dst, CmdSetGateSensitivity,
		0x00, 0x00, byte(gate), byte(gate>>8), 0x00, 0x00, // selector 0: gate
		0x01, 0x00, moving, 0x00, 0x00, 0x00, // selector 1: moving threshold
		0x02, 0x00, stationary, 0x00, 0x00, 0x00, // selector 2: stationary threshold
	), nil
}

// AppendSetMaxDistanceAndDuration appends the command that bounds detection
// range and sets the module's own presence hold time.
//
// maxMovingGate and maxStationaryGate cap which gates are considered, so they
// are how detection range is limited to the room rather than through the wall
// behind it. Both must lie between MinConfigurableGate and MaxGate.
//
// unoccupiedDuration is how long the module keeps reporting a target after it
// stops seeing one, in seconds; any detection within the window restarts it.
// Set it to zero to get the module's instantaneous verdict and leave hysteresis
// to the caller, which avoids stacking two independent hold timers whose
// combined behaviour is hard to reason about. The factory default is 5.
func AppendSetMaxDistanceAndDuration(dst []byte, maxMovingGate, maxStationaryGate uint8, unoccupiedDuration uint16) ([]byte, error) {
	if !validMaxGate(maxMovingGate) || !validMaxGate(maxStationaryGate) {
		return dst, ErrGateOutOfRange
	}
	return AppendCommand(dst, CmdSetMaxDistance,
		0x00, 0x00, maxMovingGate, 0x00, 0x00, 0x00, // selector 0: max moving gate
		0x01, 0x00, maxStationaryGate, 0x00, 0x00, 0x00, // selector 1: max stationary gate
		0x02, 0x00, byte(unoccupiedDuration), byte(unoccupiedDuration>>8), 0x00, 0x00, // selector 2: hold seconds
	), nil
}

// validMaxGate reports whether g is accepted by CmdSetMaxDistance, whose
// documented range is 2 to 8 rather than the full gate range.
func validMaxGate(g uint8) bool {
	return g >= MinConfigurableGate && g <= MaxGate
}

// AppendStartNoiseDetection appends the background noise calibration command.
//
// The module waits ten seconds, measures the per-gate noise floor for the
// requested duration, then derives and stores its own sensitivities from it.
// The space must stay empty throughout. While it runs, report frames carry
// TargetNoiseDetecting in place of a presence result.
func AppendStartNoiseDetection(dst []byte, seconds uint16) []byte {
	return AppendCommand(dst, CmdStartNoiseDetection, byte(seconds), byte(seconds>>8))
}

// AppendQueryNoiseDetection appends the command that polls calibration progress.
func AppendQueryNoiseDetection(dst []byte) []byte {
	return AppendCommand(dst, CmdQueryNoiseDetection)
}

// NoiseDetectionStatus is the progress of a background noise calibration run.
type NoiseDetectionStatus uint16

const (
	NoiseIdle     NoiseDetectionStatus = 0x0000
	NoiseRunning  NoiseDetectionStatus = 0x0001
	NoiseComplete NoiseDetectionStatus = 0x0002
)

func (s NoiseDetectionStatus) String() string {
	switch s {
	case NoiseRunning:
		return "running"
	case NoiseComplete:
		return "complete"
	default:
		return "idle"
	}
}

// ParseNoiseDetectionStatus decodes the payload of a CmdQueryNoiseDetection ACK.
func ParseNoiseDetectionStatus(data []byte) (NoiseDetectionStatus, error) {
	if err := ParseACK(data, CmdQueryNoiseDetection); err != nil {
		return NoiseIdle, err
	}
	if len(data) < 6 {
		return NoiseIdle, ErrShortPayload
	}
	return NoiseDetectionStatus(le16(data[4:])), nil
}

// GateForDistanceCM returns the maximum gate that must be enabled to cover
// distances up to cm, given a gate depth of gateWidthCM.
//
// The result is clamped to the range CmdSetMaxDistance accepts, so it is never
// below MinConfigurableGate nor above MaxGate. Pass GateWidthCM unless the
// module's distance resolution has been changed from the factory default.
func GateForDistanceCM(cm, gateWidthCM uint16) uint8 {
	if gateWidthCM == 0 {
		gateWidthCM = GateWidthCM
	}
	gate := cm / gateWidthCM
	if cm%gateWidthCM != 0 {
		gate++ // a partially covered gate is still needed
	}
	if gate > uint16(MaxGate) {
		return MaxGate
	}
	if gate < uint16(MinConfigurableGate) {
		return MinConfigurableGate
	}
	return uint8(gate)
}
