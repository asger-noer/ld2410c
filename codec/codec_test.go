package codec

import (
	"bytes"
	"errors"
	"testing"
)

// reportFrame builds a well-formed basic report frame around the given payload
// fields, so tests can describe what they mean rather than counting bytes.
func reportFrame(target uint8, movDist uint16, movEnergy uint8, statDist uint16, statEnergy uint8, detDist uint16) []byte {
	return typedReportFrame(FrameTypeBasic, target, movDist, movEnergy, statDist, statEnergy, detDist)
}

func typedReportFrame(frameType, target uint8, movDist uint16, movEnergy uint8, statDist uint16, statEnergy uint8, detDist uint16) []byte {
	data := []byte{
		frameType, 0xAA, target,
		byte(movDist), byte(movDist >> 8), movEnergy,
		byte(statDist), byte(statDist >> 8), statEnergy,
		byte(detDist), byte(detDist >> 8),
		0x55, 0x00,
	}
	return frameWith(ReportHeader, ReportTail, data)
}

func frameWith(header, tail [4]byte, data []byte) []byte {
	out := append([]byte{}, header[:]...)
	out = append(out, byte(len(data)), byte(len(data)>>8))
	out = append(out, data...)
	return append(out, tail[:]...)
}

func newScanner(t *testing.T) *Scanner {
	t.Helper()
	var sc Scanner
	if err := sc.Reset(make([]byte, 512)); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	return &sc
}

// scanAll drains every frame the scanner can currently produce.
func scanAll(t *testing.T, sc *Scanner) (kinds []Kind, payloads [][]byte) {
	t.Helper()
	for {
		kind, data, ok := sc.Next()
		if !ok {
			return kinds, payloads
		}
		kinds = append(kinds, kind)
		payloads = append(payloads, append([]byte{}, data...))
	}
}

func TestParseReport(t *testing.T) {
	// A frame carrying both a moving and a stationary target: the two channels
	// are independent, so both distance/energy pairs must survive decoding.
	frame := reportFrame(0x03, 150, 62, 210, 41, 150)
	got, err := ParseReport(frame[6 : len(frame)-4])
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}

	want := Frame{
		Target:             TargetPresence,
		MovingDistance:     150,
		MovingEnergy:       62,
		StationaryDistance: 210,
		StationaryEnergy:   41,
		DetectionDistance:  150,
	}
	if got != want {
		t.Errorf("frame mismatch\n got %+v\nwant %+v", got, want)
	}
	if !got.Target.HasMoving() || !got.Target.HasStationary() {
		t.Error("target 0x03 should report both moving and stationary")
	}
}

func TestParseReportRejectsBadMarkerAndType(t *testing.T) {
	// The head marker is 0xAA in both basic and engineering frames, so anything
	// else means the payload is not a report at all.
	badMarker := []byte{FrameTypeBasic, 0xBB, 0x03, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := ParseReport(badMarker); !errors.Is(err, ErrHeadMarker) {
		t.Errorf("bad marker: got %v, want ErrHeadMarker", err)
	}

	// The frame type is the real discriminator, and only 0x01 and 0x02 exist.
	badType := []byte{0x07, 0xAA, 0x03, 0, 0, 0, 0, 0, 0, 0, 0}
	if _, err := ParseReport(badType); !errors.Is(err, ErrFrameType) {
		t.Errorf("bad type: got %v, want ErrFrameType", err)
	}
}

// TestParseReportEngineeringFrame covers the correction that engineering mode is
// identified by the frame type at [0], not by the head marker at [1], which is
// 0xAA in both modes. Engineering frames place the basic fields at the same
// offsets and append per-gate energies, so they decode identically.
func TestParseReportEngineeringFrame(t *testing.T) {
	frame := typedReportFrame(FrameTypeEngineering, 0x03, 30, 60, 0, 57, 0)
	got, err := ParseReport(frame[6 : len(frame)-4])
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if !got.Engineering {
		t.Error("Engineering flag not set for a type 0x01 frame")
	}
	if got.MovingDistance != 30 || got.MovingEnergy != 60 || got.StationaryEnergy != 57 {
		t.Errorf("basic fields misdecoded from an engineering frame: %+v", got)
	}
}

// TestParseReportDatasheetExamples decodes the two worked examples from the
// protocol document verbatim, which pins the layout against the vendor spec
// rather than against our own frame builder.
func TestParseReportDatasheetExamples(t *testing.T) {
	// Normal mode: F4 F3 F2 F1 | 0D 00 | 02 AA 02 51 00 00 00 00 3B 00 00 55 00 | F8 F7 F6 F5
	basic := []byte{0x02, 0xAA, 0x02, 0x51, 0x00, 0x00, 0x00, 0x00, 0x3B, 0x00, 0x00, 0x55, 0x00}
	got, err := ParseReport(basic)
	if err != nil {
		t.Fatalf("basic example: %v", err)
	}
	if got.Target != TargetStationary {
		t.Errorf("target = %v, want stationary", got.Target)
	}
	if got.MovingDistance != 0x51 || got.StationaryEnergy != 0x3B {
		t.Errorf("basic example misdecoded: %+v", got)
	}
	if got.Engineering {
		t.Error("basic example flagged as engineering")
	}

	// Engineering mode, truncated to the basic fields it shares with the above.
	eng := []byte{0x01, 0xAA, 0x03, 0x1E, 0x00, 0x3C, 0x00, 0x00, 0x39, 0x00, 0x00}
	got, err = ParseReport(eng)
	if err != nil {
		t.Fatalf("engineering example: %v", err)
	}
	if got.Target != TargetPresence || got.MovingDistance != 0x1E ||
		got.MovingEnergy != 0x3C || got.StationaryEnergy != 0x39 {
		t.Errorf("engineering example misdecoded: %+v", got)
	}
}

func TestParseReportRejectsShortPayload(t *testing.T) {
	if _, err := ParseReport([]byte{0x02, 0xAA, 0x03}); !errors.Is(err, ErrShortPayload) {
		t.Errorf("got %v, want ErrShortPayload", err)
	}
}

func TestTargetStateFlags(t *testing.T) {
	for _, tc := range []struct {
		state            TargetState
		moving, stat, on bool
		str              string
	}{
		{TargetNone, false, false, false, "none"},
		{TargetMoving, true, false, true, "moving"},
		{TargetStationary, false, true, true, "stationary"},
		{TargetPresence, true, true, true, "moving+stationary"},

		// Calibration status codes share the byte but are not bit flags. Read
		// naively, 0x05 has bit 0 set and would report a moving target, and 0x06
		// has bit 1 set and would report a stationary one, so an empty room
		// under calibration would look occupied.
		{TargetNoiseDetecting, false, false, false, "calibrating"},
		{TargetNoiseSucceeded, false, false, false, "calibration-succeeded"},
		{TargetNoiseFailed, false, false, false, "calibration-failed"},
	} {
		t.Run(tc.str, func(t *testing.T) {
			if got := tc.state.HasMoving(); got != tc.moving {
				t.Errorf("HasMoving = %v, want %v", got, tc.moving)
			}
			if got := tc.state.HasStationary(); got != tc.stat {
				t.Errorf("HasStationary = %v, want %v", got, tc.stat)
			}
			if got := tc.state.Detected(); got != tc.on {
				t.Errorf("Detected = %v, want %v", got, tc.on)
			}
			if got := tc.state.String(); got != tc.str {
				t.Errorf("String = %q, want %q", got, tc.str)
			}
		})
	}
}

func TestTargetStateClassification(t *testing.T) {
	for s := TargetNone; s <= TargetPresence; s++ {
		if !s.IsPresence() || s.IsCalibration() {
			t.Errorf("%#02x should classify as presence", uint8(s))
		}
	}
	for s := TargetNoiseDetecting; s <= TargetNoiseFailed; s++ {
		if s.IsPresence() || !s.IsCalibration() {
			t.Errorf("%#02x should classify as calibration", uint8(s))
		}
	}
}

func TestScannerSingleFrame(t *testing.T) {
	sc := newScanner(t)
	sc.Write(reportFrame(0x01, 100, 50, 0, 0, 100)) //nolint:errcheck

	kind, data, ok := sc.Next()
	if !ok {
		t.Fatal("expected a frame")
	}
	if kind != KindReport {
		t.Errorf("kind = %v, want report", kind)
	}
	if _, err := ParseReport(data); err != nil {
		t.Errorf("ParseReport: %v", err)
	}
	if _, _, ok := sc.Next(); ok {
		t.Error("expected no second frame")
	}
}

func TestScannerResyncsPastGarbagePrefix(t *testing.T) {
	// Attaching to an already-running module means starting mid-stream. The
	// leading junk includes a lone 0xF4 to make sure a false header start does
	// not consume the real frame behind it.
	sc := newScanner(t)
	sc.Write([]byte{0xFF, 0x00, 0xF4, 0x12, 0xAB})  //nolint:errcheck
	sc.Write(reportFrame(0x02, 0, 0, 200, 35, 200)) //nolint:errcheck

	kind, data, ok := sc.Next()
	if !ok {
		t.Fatal("expected the frame after the garbage prefix")
	}
	if kind != KindReport {
		t.Errorf("kind = %v, want report", kind)
	}
	f, err := ParseReport(data)
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if f.StationaryDistance != 200 || f.StationaryEnergy != 35 {
		t.Errorf("payload corrupted: %+v", f)
	}
	if sc.Discarded() == 0 {
		t.Error("expected the discarded counter to record the skipped prefix")
	}
}

func TestScannerHandlesTruncatedFrame(t *testing.T) {
	// Bulk reads split frames arbitrarily. A partial frame must yield nothing
	// and then complete once the remainder arrives, without losing bytes.
	full := reportFrame(0x01, 75, 80, 0, 0, 75)
	for _, split := range []int{1, 4, 6, 10, len(full) - 1} {
		sc := newScanner(t)
		sc.Write(full[:split]) //nolint:errcheck
		if _, _, ok := sc.Next(); ok {
			t.Fatalf("split=%d: frame reported before it was complete", split)
		}
		sc.Write(full[split:]) //nolint:errcheck
		kind, data, ok := sc.Next()
		if !ok {
			t.Fatalf("split=%d: frame not recovered after remainder arrived", split)
		}
		if kind != KindReport {
			t.Errorf("split=%d: kind = %v, want report", split, kind)
		}
		f, err := ParseReport(data)
		if err != nil {
			t.Fatalf("split=%d: ParseReport: %v", split, err)
		}
		if f.MovingDistance != 75 || f.MovingEnergy != 80 {
			t.Errorf("split=%d: payload corrupted: %+v", split, f)
		}
	}
}

func TestScannerRejectsBadTailAndRecovers(t *testing.T) {
	// A frame whose tail does not match is not a frame. The scanner must step
	// forward far enough to find the next real one rather than trusting the
	// bogus length field.
	bad := reportFrame(0x01, 100, 50, 0, 0, 100)
	bad[len(bad)-1] = 0x00
	good := reportFrame(0x02, 0, 0, 300, 20, 300)

	sc := newScanner(t)
	sc.Write(bad)  //nolint:errcheck
	sc.Write(good) //nolint:errcheck

	kinds, payloads := scanAll(t, sc)
	if len(kinds) != 1 {
		t.Fatalf("got %d frames, want 1", len(kinds))
	}
	f, err := ParseReport(payloads[0])
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if f.StationaryDistance != 300 {
		t.Errorf("recovered the wrong frame: %+v", f)
	}
}

func TestScannerInterleavedReportAndConfigFrames(t *testing.T) {
	// The module keeps streaming reports while a command ACK is outstanding, so
	// the scanner has to separate the two streams by header rather than assume
	// the next frame is the ACK.
	ack := frameWith(ConfigHeader, ConfigTail, []byte{0xFF, 0x01, 0x00, 0x00})
	sc := newScanner(t)
	sc.Write(reportFrame(0x01, 100, 50, 0, 0, 100)) //nolint:errcheck
	sc.Write(ack)                                   //nolint:errcheck
	sc.Write(reportFrame(0x00, 0, 0, 0, 0, 0))      //nolint:errcheck

	kinds, payloads := scanAll(t, sc)
	wantKinds := []Kind{KindReport, KindConfig, KindReport}
	if len(kinds) != len(wantKinds) {
		t.Fatalf("got %d frames, want %d", len(kinds), len(wantKinds))
	}
	for i, want := range wantKinds {
		if kinds[i] != want {
			t.Errorf("frame %d: kind = %v, want %v", i, kinds[i], want)
		}
	}
	if err := ParseACK(payloads[1], CmdEnableConfig); err != nil {
		t.Errorf("ParseACK on the interleaved config frame: %v", err)
	}
}

func TestScannerRejectsOversizeLength(t *testing.T) {
	// A corrupt length field must not be trusted; the scanner should treat the
	// header as spurious and find the following real frame.
	var bogus []byte
	bogus = append(bogus, ReportHeader[:]...)
	bogus = append(bogus, 0xFF, 0xFF) // claims 65535 bytes of payload
	good := reportFrame(0x01, 50, 90, 0, 0, 50)

	sc := newScanner(t)
	sc.Write(bogus) //nolint:errcheck
	sc.Write(good)  //nolint:errcheck

	kinds, payloads := scanAll(t, sc)
	if len(kinds) != 1 {
		t.Fatalf("got %d frames, want 1", len(kinds))
	}
	f, err := ParseReport(payloads[0])
	if err != nil {
		t.Fatalf("ParseReport: %v", err)
	}
	if f.MovingEnergy != 90 {
		t.Errorf("recovered the wrong frame: %+v", f)
	}
}

func TestScannerWriteEvictsOldestOnOverflow(t *testing.T) {
	// When the consumer falls behind, the newest frame is the one worth keeping.
	// Verify an overflow drops old bytes, records the overrun, and still yields
	// a decodable recent frame.
	var sc Scanner
	if err := sc.Reset(make([]byte, MaxDataLen+scannerOverhead)); err != nil {
		t.Fatalf("Reset: %v", err)
	}
	for i := range 20 {
		sc.Write(reportFrame(0x01, uint16(i), uint8(i), 0, 0, uint16(i))) //nolint:errcheck
	}
	if sc.Overruns() == 0 {
		t.Error("expected the overrun counter to fire")
	}
	kinds, _ := scanAll(t, &sc)
	if len(kinds) == 0 {
		t.Error("expected at least one frame to survive the eviction")
	}
}

func TestScannerResetRejectsSmallBuffer(t *testing.T) {
	var sc Scanner
	if err := sc.Reset(make([]byte, 8)); !errors.Is(err, ErrScannerBufferTooSmall) {
		t.Errorf("got %v, want ErrScannerBufferTooSmall", err)
	}
}

func TestParseACK(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		cmd  uint16
		want error
	}{
		{"success", []byte{0xFF, 0x01, 0x00, 0x00}, CmdEnableConfig, nil},
		{"gate sensitivity success", []byte{0x64, 0x01, 0x00, 0x00}, CmdSetGateSensitivity, nil},
		{"firmware success", []byte{0xA0, 0x01, 0x00, 0x00}, CmdReadFirmware, nil},
		{"wrong command", []byte{0x60, 0x01, 0x00, 0x00}, CmdSetGateSensitivity, ErrACKCommand},
		{"missing ack bit", []byte{0xFF, 0x00, 0x00, 0x00}, CmdEnableConfig, ErrACKCommand},
		{"failure status", []byte{0xFF, 0x01, 0x01, 0x00}, CmdEnableConfig, ErrACKStatus},
		{"short", []byte{0xFF, 0x01}, CmdEnableConfig, ErrShortPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ParseACK(tc.data, tc.cmd); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// paramsPayload builds a read-parameters ACK payload for a module reporting
// maxGate as its highest gate. The sensitivity blocks are sized by maxGate, so
// this is where a hardcoded offset would break.
func paramsPayload(maxGate uint8, moving, stationary []uint8, duration uint16) []byte {
	data := []byte{0x61, 0x01, 0x00, 0x00, 0xAA, maxGate, maxGate, maxGate}
	data = append(data, moving...)
	data = append(data, stationary...)
	return append(data, byte(duration), byte(duration>>8))
}

func TestParseParameters(t *testing.T) {
	moving := []uint8{31, 22, 17, 16, 16, 13, 16, 18, 15}
	stationary := []uint8{10, 10, 13, 13, 12, 12, 12, 12, 12}

	got, err := ParseParameters(paramsPayload(8, moving, stationary, 30))
	if err != nil {
		t.Fatalf("ParseParameters: %v", err)
	}
	if got.MaxDistanceGate != 8 || got.UnoccupiedDuration != 30 {
		t.Errorf("unexpected header fields: %+v", got)
	}
	for i := range Gates {
		if got.MovingSensitivity[i] != moving[i] {
			t.Errorf("moving[%d] = %d, want %d", i, got.MovingSensitivity[i], moving[i])
		}
		if got.StationarySensitivity[i] != stationary[i] {
			t.Errorf("stationary[%d] = %d, want %d", i, got.StationarySensitivity[i], stationary[i])
		}
	}
}

func TestParseParametersShorterGateCount(t *testing.T) {
	// A module configured to a smaller maximum gate sends shorter sensitivity
	// blocks, which moves the duration field. Computing the offsets from
	// MaxDistanceGate is what makes this work.
	moving := []uint8{31, 22, 17, 16}
	stationary := []uint8{10, 10, 13, 13}

	got, err := ParseParameters(paramsPayload(3, moving, stationary, 5))
	if err != nil {
		t.Fatalf("ParseParameters: %v", err)
	}
	if got.UnoccupiedDuration != 5 {
		t.Errorf("UnoccupiedDuration = %d, want 5", got.UnoccupiedDuration)
	}
	if got.MovingSensitivity[3] != 16 {
		t.Errorf("MovingSensitivity[3] = %d, want 16", got.MovingSensitivity[3])
	}
	if got.MovingSensitivity[4] != 0 {
		t.Errorf("MovingSensitivity[4] = %d, want 0 for an unreported gate", got.MovingSensitivity[4])
	}
}

func TestParseParametersErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want error
	}{
		{"bad ack", []byte{0x60, 0x01, 0x00, 0x00, 0xAA, 8}, ErrACKCommand},
		{"missing marker", []byte{0x61, 0x01, 0x00, 0x00, 0xBB, 8, 8, 8}, ErrParamsMarker},
		{"truncated header", []byte{0x61, 0x01, 0x00, 0x00, 0xAA}, ErrShortPayload},
		{"truncated body", []byte{0x61, 0x01, 0x00, 0x00, 0xAA, 8, 8, 8, 1, 2}, ErrShortPayload},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseParameters(tc.data); !errors.Is(err, tc.want) {
				t.Errorf("got %v, want %v", err, tc.want)
			}
		})
	}
}

// TestParseParametersOverlargeGateCount guards the clamp: a malformed reply
// claiming more gates than exist must not drive an out-of-range write.
func TestParseParametersOverlargeGateCount(t *testing.T) {
	data := []byte{0x61, 0x01, 0x00, 0x00, 0xAA, 200, 8, 8}
	data = append(data, bytes.Repeat([]byte{5}, 64)...)
	if _, err := ParseParameters(data); err != nil && !errors.Is(err, ErrShortPayload) {
		t.Errorf("unexpected error kind: %v", err)
	}
}

// TestCommandRoundTrip feeds each generated command back through the scanner.
// Anything mis-framed shows up immediately as an unparseable frame, which makes
// this a cheap check on every builder at once.
func TestCommandRoundTrip(t *testing.T) {
	setGate, err := AppendSetGateSensitivity(nil, 4, 30, 20)
	if err != nil {
		t.Fatalf("AppendSetGateSensitivity: %v", err)
	}
	setAll, err := AppendSetGateSensitivity(nil, AllGates, 40, 25)
	if err != nil {
		t.Fatalf("AppendSetGateSensitivity(AllGates): %v", err)
	}
	setMax, err := AppendSetMaxDistanceAndDuration(nil, 5, 5, 0)
	if err != nil {
		t.Fatalf("AppendSetMaxDistanceAndDuration: %v", err)
	}

	for _, tc := range []struct {
		name  string
		frame []byte
		cmd   uint16
	}{
		{"enable config", AppendEnableConfig(nil), CmdEnableConfig},
		{"end config", AppendEndConfig(nil), CmdEndConfig},
		{"read parameters", AppendReadParameters(nil), CmdReadParameters},
		{"read firmware", AppendReadFirmware(nil), CmdReadFirmware},
		{"enable eng mode", AppendEnableEngineeringMode(nil), CmdEnableEngMode},
		{"disable eng mode", AppendDisableEngineeringMode(nil), CmdDisableEngMode},
		{"restart", AppendRestartModule(nil), CmdRestartModule},
		{"factory reset", AppendFactoryReset(nil), CmdFactoryReset},
		{"set gate", setGate, CmdSetGateSensitivity},
		{"set all gates", setAll, CmdSetGateSensitivity},
		{"set max distance", setMax, CmdSetMaxDistance},
		{"start noise detection", AppendStartNoiseDetection(nil, 10), CmdStartNoiseDetection},
		{"query noise detection", AppendQueryNoiseDetection(nil), CmdQueryNoiseDetection},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := newScanner(t)
			sc.Write(tc.frame) //nolint:errcheck
			kind, data, ok := sc.Next()
			if !ok {
				t.Fatal("generated frame did not scan back")
			}
			if kind != KindConfig {
				t.Errorf("kind = %v, want config", kind)
			}
			if got := le16(data); got != tc.cmd {
				t.Errorf("command word = %#04x, want %#04x", got, tc.cmd)
			}
			if sc.Discarded() != 0 {
				t.Errorf("generated frame required %d bytes of resync", sc.Discarded())
			}
		})
	}
}

// TestAppendSetGateSensitivityLayout pins the exact byte layout, since a
// selector or endianness slip would be silently accepted by the module and only
// show up as mysteriously wrong thresholds on real hardware.
func TestAppendSetGateSensitivityLayout(t *testing.T) {
	got, err := AppendSetGateSensitivity(nil, 4, 30, 20)
	if err != nil {
		t.Fatalf("AppendSetGateSensitivity: %v", err)
	}
	want := []byte{
		0xFD, 0xFC, 0xFB, 0xFA,
		0x14, 0x00, // data length 20
		0x64, 0x00, // command 0x0064
		0x00, 0x00, 0x04, 0x00, 0x00, 0x00, // gate 4
		0x01, 0x00, 30, 0x00, 0x00, 0x00, // moving 30
		0x02, 0x00, 20, 0x00, 0x00, 0x00, // stationary 20
		0x04, 0x03, 0x02, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("layout mismatch\n got %#v\nwant %#v", got, want)
	}
}

func TestAppendSetMaxDistanceAndDurationLayout(t *testing.T) {
	got, err := AppendSetMaxDistanceAndDuration(nil, 5, 5, 300)
	if err != nil {
		t.Fatalf("AppendSetMaxDistanceAndDuration: %v", err)
	}
	want := []byte{
		0xFD, 0xFC, 0xFB, 0xFA,
		0x14, 0x00,
		0x60, 0x00,
		0x00, 0x00, 0x05, 0x00, 0x00, 0x00, // max moving gate 5
		0x01, 0x00, 0x05, 0x00, 0x00, 0x00, // max stationary gate 5
		0x02, 0x00, 0x2C, 0x01, 0x00, 0x00, // duration 300 = 0x012C little-endian
		0x04, 0x03, 0x02, 0x01,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("layout mismatch\n got %#v\nwant %#v", got, want)
	}
}

func TestCommandBuilderValidation(t *testing.T) {
	if _, err := AppendSetGateSensitivity(nil, 3, 101, 20); !errors.Is(err, ErrSensitivity) {
		t.Errorf("moving 101: got %v, want ErrSensitivity", err)
	}
	if _, err := AppendSetGateSensitivity(nil, 3, 20, 101); !errors.Is(err, ErrSensitivity) {
		t.Errorf("stationary 101: got %v, want ErrSensitivity", err)
	}
	if _, err := AppendSetGateSensitivity(nil, Gates, 20, 20); !errors.Is(err, ErrGateOutOfRange) {
		t.Errorf("gate 9: got %v, want ErrGateOutOfRange", err)
	}
	// A sensitivity of 100 is legal and documented as "never detect here".
	if _, err := AppendSetGateSensitivity(nil, 3, 100, 100); err != nil {
		t.Errorf("sensitivity 100 should be accepted: %v", err)
	}

	// CmdSetMaxDistance accepts gates 2 to 8 only, so 0, 1 and 9 are all
	// rejected rather than just those above the gate count.
	for _, gate := range []uint8{0, 1, Gates} {
		if _, err := AppendSetMaxDistanceAndDuration(nil, gate, 5, 0); !errors.Is(err, ErrGateOutOfRange) {
			t.Errorf("max moving gate %d: got %v, want ErrGateOutOfRange", gate, err)
		}
		if _, err := AppendSetMaxDistanceAndDuration(nil, 5, gate, 0); !errors.Is(err, ErrGateOutOfRange) {
			t.Errorf("max stationary gate %d: got %v, want ErrGateOutOfRange", gate, err)
		}
	}
	for gate := MinConfigurableGate; gate <= MaxGate; gate++ {
		if _, err := AppendSetMaxDistanceAndDuration(nil, gate, gate, 0); err != nil {
			t.Errorf("max gate %d should be accepted: %v", gate, err)
		}
	}
}

// TestDatasheetCommandExamples compares generated frames against the byte
// sequences printed in the protocol document, so a selector or endianness slip
// is caught against the vendor spec rather than against our own assumptions.
func TestDatasheetCommandExamples(t *testing.T) {
	// 2.2.1 enable configuration
	wantEnable := []byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xFF, 0x00, 0x01, 0x00, 0x04, 0x03, 0x02, 0x01}
	if got := AppendEnableConfig(nil); !bytes.Equal(got, wantEnable) {
		t.Errorf("enable config\n got %#v\nwant %#v", got, wantEnable)
	}

	// 2.2.2 end configuration
	wantEnd := []byte{0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0xFE, 0x00, 0x04, 0x03, 0x02, 0x01}
	if got := AppendEndConfig(nil); !bytes.Equal(got, wantEnd) {
		t.Errorf("end config\n got %#v\nwant %#v", got, wantEnd)
	}

	// 2.2.3 max distance gate 8 both, unoccupied duration 5 s
	wantMax := []byte{
		0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x60, 0x00,
		0x00, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x08, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x05, 0x00, 0x00, 0x00,
		0x04, 0x03, 0x02, 0x01,
	}
	got, err := AppendSetMaxDistanceAndDuration(nil, 8, 8, 5)
	if err != nil {
		t.Fatalf("AppendSetMaxDistanceAndDuration: %v", err)
	}
	if !bytes.Equal(got, wantMax) {
		t.Errorf("set max distance\n got %#v\nwant %#v", got, wantMax)
	}

	// 2.2.4 read parameters
	wantRead := []byte{0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0x61, 0x00, 0x04, 0x03, 0x02, 0x01}
	if got := AppendReadParameters(nil); !bytes.Equal(got, wantRead) {
		t.Errorf("read parameters\n got %#v\nwant %#v", got, wantRead)
	}

	// 2.2.7 gate 3, motion 40, stationary 40
	wantGate := []byte{
		0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x64, 0x00,
		0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x04, 0x03, 0x02, 0x01,
	}
	got, err = AppendSetGateSensitivity(nil, 3, 40, 40)
	if err != nil {
		t.Fatalf("AppendSetGateSensitivity: %v", err)
	}
	if !bytes.Equal(got, wantGate) {
		t.Errorf("set gate 3\n got %#v\nwant %#v", got, wantGate)
	}

	// 2.2.7 all gates via 0xFFFF
	wantAll := []byte{
		0xFD, 0xFC, 0xFB, 0xFA, 0x14, 0x00, 0x64, 0x00,
		0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
		0x01, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x02, 0x00, 0x28, 0x00, 0x00, 0x00,
		0x04, 0x03, 0x02, 0x01,
	}
	got, err = AppendSetGateSensitivity(nil, AllGates, 40, 40)
	if err != nil {
		t.Fatalf("AppendSetGateSensitivity(AllGates): %v", err)
	}
	if !bytes.Equal(got, wantAll) {
		t.Errorf("set all gates\n got %#v\nwant %#v", got, wantAll)
	}

	// 2.2.20 start noise detection, 10 s
	wantNoise := []byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0x0B, 0x00, 0x0A, 0x00, 0x04, 0x03, 0x02, 0x01}
	if got := AppendStartNoiseDetection(nil, 10); !bytes.Equal(got, wantNoise) {
		t.Errorf("start noise detection\n got %#v\nwant %#v", got, wantNoise)
	}

	// 2.2.21 query noise detection
	wantQuery := []byte{0xFD, 0xFC, 0xFB, 0xFA, 0x02, 0x00, 0x1B, 0x00, 0x04, 0x03, 0x02, 0x01}
	if got := AppendQueryNoiseDetection(nil); !bytes.Equal(got, wantQuery) {
		t.Errorf("query noise detection\n got %#v\nwant %#v", got, wantQuery)
	}
}

// TestDatasheetACKExamples parses the ACK frames printed in the protocol
// document, including the eight-byte enable-config reply that carries a protocol
// version and buffer size after the status word.
func TestDatasheetACKExamples(t *testing.T) {
	for _, tc := range []struct {
		name  string
		frame []byte
		cmd   uint16
	}{
		{
			"enable config",
			[]byte{0xFD, 0xFC, 0xFB, 0xFA, 0x08, 0x00, 0xFF, 0x01, 0x00, 0x00, 0x01, 0x00, 0x40, 0x00, 0x04, 0x03, 0x02, 0x01},
			CmdEnableConfig,
		},
		{
			"end config",
			[]byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xFE, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01},
			CmdEndConfig,
		},
		{
			"set max distance",
			[]byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0x60, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01},
			CmdSetMaxDistance,
		},
		{
			"set gate sensitivity",
			[]byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0x64, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01},
			CmdSetGateSensitivity,
		},
		{
			"restart",
			[]byte{0xFD, 0xFC, 0xFB, 0xFA, 0x04, 0x00, 0xA3, 0x01, 0x00, 0x00, 0x04, 0x03, 0x02, 0x01},
			CmdRestartModule,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			sc := newScanner(t)
			sc.Write(tc.frame) //nolint:errcheck
			kind, data, ok := sc.Next()
			if !ok {
				t.Fatal("datasheet ACK frame did not scan")
			}
			if kind != KindConfig {
				t.Errorf("kind = %v, want config", kind)
			}
			if err := ParseACK(data, tc.cmd); err != nil {
				t.Errorf("ParseACK: %v", err)
			}
		})
	}
}

// TestDatasheetReadParametersACK parses the full read-parameters reply from
// section 2.2.4 byte for byte. It is the most offset-sensitive frame in the
// protocol, since the two sensitivity blocks are sized by the reported gate
// count and the duration sits after both.
func TestDatasheetReadParametersACK(t *testing.T) {
	frame := []byte{
		0xFD, 0xFC, 0xFB, 0xFA, 0x1C, 0x00,
		0x61, 0x01, 0x00, 0x00,
		0xAA, 0x08, 0x08, 0x08,
		0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, 0x14, // moving, 9 gates at 20
		0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, 0x19, // stationary, 9 gates at 25
		0x05, 0x00, // unoccupied duration 5 s
		0x04, 0x03, 0x02, 0x01,
	}

	sc := newScanner(t)
	sc.Write(frame) //nolint:errcheck
	kind, data, ok := sc.Next()
	if !ok {
		t.Fatal("datasheet parameters frame did not scan")
	}
	if kind != KindConfig {
		t.Fatalf("kind = %v, want config", kind)
	}

	p, err := ParseParameters(data)
	if err != nil {
		t.Fatalf("ParseParameters: %v", err)
	}
	if p.MaxDistanceGate != 8 || p.MaxMovingDistanceGate != 8 || p.MaxStationaryDistanceGate != 8 {
		t.Errorf("gate fields misdecoded: %+v", p)
	}
	if p.UnoccupiedDuration != 5 {
		t.Errorf("UnoccupiedDuration = %d, want 5", p.UnoccupiedDuration)
	}
	for i := range Gates {
		if p.MovingSensitivity[i] != 20 {
			t.Errorf("MovingSensitivity[%d] = %d, want 20", i, p.MovingSensitivity[i])
		}
		if p.StationarySensitivity[i] != 25 {
			t.Errorf("StationarySensitivity[%d] = %d, want 25", i, p.StationarySensitivity[i])
		}
	}
}

// TestAppendCommandReusesBuffer covers the append-to-dst contract that lets a
// configuration session build every command in one scratch buffer without
// allocating.
func TestAppendCommandReusesBuffer(t *testing.T) {
	buf := make([]byte, 0, 128)
	buf = AppendEnableConfig(buf)
	first := len(buf)
	buf = AppendEndConfig(buf)

	sc := newScanner(t)
	sc.Write(buf) //nolint:errcheck
	kinds, payloads := scanAll(t, sc)
	if len(kinds) != 2 {
		t.Fatalf("got %d frames, want 2", len(kinds))
	}
	if got := le16(payloads[0]); got != CmdEnableConfig {
		t.Errorf("first command = %#04x, want %#04x", got, CmdEnableConfig)
	}
	if got := le16(payloads[1]); got != CmdEndConfig {
		t.Errorf("second command = %#04x, want %#04x", got, CmdEndConfig)
	}
	if first >= len(buf) {
		t.Error("second append did not extend the buffer")
	}
}

func TestGateForDistanceCM(t *testing.T) {
	for _, tc := range []struct {
		cm    uint16
		width uint16
		want  uint8
	}{
		// CmdSetMaxDistance accepts only gates 2 to 8, so short distances clamp
		// up to 2 rather than down to 0.
		{0, GateWidthCM, MinConfigurableGate},
		{75, GateWidthCM, MinConfigurableGate},
		{150, GateWidthCM, MinConfigurableGate},
		{160, GateWidthCM, 3},  // spills into gate 2, so gate 3 is needed
		{300, GateWidthCM, 4},  // exactly four gates deep
		{675, GateWidthCM, 8},  // full nine-gate range
		{1000, GateWidthCM, 8}, // clamped down to the maximum

		// Fine resolution packs the same gate count into a shorter range.
		{160, GateWidthFineCM, 8},
		{100, GateWidthFineCM, 5},

		// A zero width falls back to the factory default rather than dividing by
		// zero.
		{300, 0, 4},
	} {
		if got := GateForDistanceCM(tc.cm, tc.width); got != tc.want {
			t.Errorf("GateForDistanceCM(%d, %d) = %d, want %d", tc.cm, tc.width, got, tc.want)
		}
	}
}

func TestParseNoiseDetectionStatus(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		want NoiseDetectionStatus
		str  string
	}{
		{"idle", []byte{0x1B, 0x01, 0x00, 0x00, 0x00, 0x00}, NoiseIdle, "idle"},
		{"running", []byte{0x1B, 0x01, 0x00, 0x00, 0x01, 0x00}, NoiseRunning, "running"},
		{"complete", []byte{0x1B, 0x01, 0x00, 0x00, 0x02, 0x00}, NoiseComplete, "complete"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseNoiseDetectionStatus(tc.data)
			if err != nil {
				t.Fatalf("ParseNoiseDetectionStatus: %v", err)
			}
			if got != tc.want {
				t.Errorf("status = %v, want %v", got, tc.want)
			}
			if got.String() != tc.str {
				t.Errorf("String = %q, want %q", got.String(), tc.str)
			}
		})
	}

	if _, err := ParseNoiseDetectionStatus([]byte{0x1B, 0x01, 0x00, 0x00}); !errors.Is(err, ErrShortPayload) {
		t.Errorf("truncated: got %v, want ErrShortPayload", err)
	}
	if _, err := ParseNoiseDetectionStatus([]byte{0x0B, 0x01, 0x00, 0x00, 0x00, 0x00}); !errors.Is(err, ErrACKCommand) {
		t.Errorf("wrong command: got %v, want ErrACKCommand", err)
	}
}
