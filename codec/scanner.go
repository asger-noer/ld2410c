package codec

import "errors"

// Kind identifies which of the two frame types a scanner produced.
type Kind uint8

const (
	KindNone Kind = iota
	// KindReport is a streaming measurement frame (F4 F3 F2 F1).
	KindReport
	// KindConfig is a command or acknowledgement frame (FD FC FB FA).
	KindConfig
)

func (k Kind) String() string {
	switch k {
	case KindReport:
		return "report"
	case KindConfig:
		return "config"
	default:
		return "none"
	}
}

// ErrScannerBufferTooSmall is returned by Reset when the supplied buffer cannot
// hold a maximum-size frame.
var ErrScannerBufferTooSmall = errors.New("ld2410c: scanner buffer too small")

// scannerOverhead is the non-payload part of a frame: 4 header + 2 length +
// 4 tail bytes.
const scannerOverhead = 10

// Scanner extracts whole frames from a byte stream that may start mid-frame,
// contain interleaved frame types, or contain outright garbage.
//
// It exists because the module transmits continuously and asynchronously: a
// reader can attach at any point, and report frames keep arriving while a
// command ACK is outstanding. Byte-at-a-time header hunting handles that too,
// but at 256000 baud it costs far more scheduler time than buffering a bulk read
// and walking it in memory.
//
// Scanner performs no allocation after Reset and holds no lock; callers are
// expected to own it from a single goroutine.
//
// Typical use:
//
//	n, _ := uart.Read(chunk)
//	sc.Write(chunk[:n])
//	for {
//		kind, data, ok := sc.Next()
//		if !ok {
//			break
//		}
//		// handle frame
//	}
type Scanner struct {
	buf  []byte // caller-supplied working buffer
	n    int    // bytes currently valid in buf
	data [MaxDataLen]byte

	// Counters for diagnostics. They saturate rather than wrap so a long-lived
	// sensor cannot silently reset them.
	discarded uint32 // bytes dropped while resynchronising
	overruns  uint32 // Write calls that had to evict unread bytes
}

// Reset prepares the scanner to use buf as its working area and clears any
// buffered state. buf must be large enough for one maximum-size frame.
func (s *Scanner) Reset(buf []byte) error {
	if len(buf) < MaxDataLen+scannerOverhead {
		return ErrScannerBufferTooSmall
	}
	s.buf = buf
	s.n = 0
	s.discarded = 0
	s.overruns = 0
	return nil
}

// Discarded returns the number of bytes dropped while resynchronising, and
// Overruns the number of writes that had to evict unread data. Both are useful
// as health signals: a steadily climbing count means the reader is not keeping
// up or the wiring is noisy.
func (s *Scanner) Discarded() uint32 { return s.discarded }
func (s *Scanner) Overruns() uint32  { return s.overruns }

// Write appends p to the scanner's buffer, implementing io.Writer.
//
// If p does not fit, the oldest unread bytes are evicted to make room. Dropping
// stale bytes is the right trade for a sensor stream: the newest frame is the
// one that matters, and a partially consumed backlog is worth less than
// staying current. Write never returns a short count or an error.
func (s *Scanner) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	// A write larger than the whole buffer can only be satisfied by its tail.
	if len(p) >= len(s.buf) {
		s.overruns++
		s.discarded += uint32(s.n + len(p) - len(s.buf))
		s.n = copy(s.buf, p[len(p)-len(s.buf):])
		return len(p), nil
	}

	if free := len(s.buf) - s.n; len(p) > free {
		evict := len(p) - free
		copy(s.buf, s.buf[evict:s.n])
		s.n -= evict
		s.overruns++
		s.discarded += uint32(evict)
	}

	s.n += copy(s.buf[s.n:], p)
	return len(p), nil
}

// Next returns the next complete frame, or ok == false when more input is
// needed.
//
// The returned slice points into scanner-owned storage and is valid only until
// the following call to Next or Write. Callers that retain the payload must copy
// it. In practice the payload is decoded immediately by ParseReport or ParseACK,
// both of which return values.
func (s *Scanner) Next() (Kind, []byte, bool) {
	for {
		idx, kind := s.findHeader()
		if idx < 0 {
			// Nothing that could begin a header. Keep only the trailing bytes
			// that a header might still be split across.
			s.resync(s.n - min(s.n, len(ReportHeader)-1))
			return KindNone, nil, false
		}
		s.resync(idx)
		if kind == KindNone {
			// A partial header runs off the end of the buffer; wait for the rest.
			return KindNone, nil, false
		}

		// Header is now at offset 0. The length field follows it.
		if s.n < len(ReportHeader)+2 {
			return KindNone, nil, false
		}
		dataLen := int(le16(s.buf[4:]))
		if dataLen > MaxDataLen {
			// Implausible length: this was not really a frame start.
			s.resync(1)
			continue
		}

		total := scannerOverhead + dataLen
		if s.n < total {
			return KindNone, nil, false
		}

		if !s.tailMatches(kind, total-len(ReportTail)) {
			// Header-like bytes inside a corrupt or unrecognised frame. Step one
			// byte forward rather than skipping the whole claimed length, so a
			// real header hiding inside the discarded span is still found.
			s.resync(1)
			continue
		}

		n := copy(s.data[:], s.buf[len(ReportHeader)+2:total-len(ReportTail)])
		s.discard(total)
		return kind, s.data[:n], true
	}
}

// findHeader locates the earliest position in the buffer that begins a frame
// header.
//
// It returns the offset together with the frame kind. A kind of KindNone with a
// non-negative offset means a header is partially present at the end of the
// buffer and the caller should wait for more bytes. An offset of -1 means no
// position could begin a header.
func (s *Scanner) findHeader() (int, Kind) {
	for i := range s.n {
		if r := matchPrefix(s.buf[i:s.n], ReportHeader[:]); r != noMatch {
			if r == full {
				return i, KindReport
			}
			return i, KindNone // partial, needs more input
		}
		if r := matchPrefix(s.buf[i:s.n], ConfigHeader[:]); r != noMatch {
			if r == full {
				return i, KindConfig
			}
			return i, KindNone
		}
	}
	return -1, KindNone
}

type prefixResult uint8

const (
	noMatch prefixResult = iota
	partial
	full
)

// matchPrefix reports whether want is a prefix of have (full), whether have is
// a strict prefix of want and so could still become one (partial), or neither.
func matchPrefix(have, want []byte) prefixResult {
	n := min(len(have), len(want))
	for i := range n {
		if have[i] != want[i] {
			return noMatch
		}
	}
	if n == len(want) {
		return full
	}
	return partial
}

// tailMatches reports whether the four bytes at off are the tail belonging to
// kind.
func (s *Scanner) tailMatches(kind Kind, off int) bool {
	want := ReportTail
	if kind == KindConfig {
		want = ConfigTail
	}
	for i, b := range want {
		if s.buf[off+i] != b {
			return false
		}
	}
	return true
}

// resync drops the first n bytes as unusable, recording them in the discarded
// counter. It is used for every drop that is not part of a successfully decoded
// frame, so the counter measures only genuine stream damage or mid-stream
// attachment rather than normal throughput.
func (s *Scanner) resync(n int) {
	if n <= 0 {
		return
	}
	s.discarded += uint32(min(n, s.n))
	s.discard(n)
}

// discard drops the first n bytes, compacting the remainder to the front.
func (s *Scanner) discard(n int) {
	if n <= 0 {
		return
	}
	if n >= s.n {
		s.n = 0
		return
	}
	copy(s.buf, s.buf[n:s.n])
	s.n -= n
}
