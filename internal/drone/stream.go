package drone

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"time"
)

// Stream Header: 16 bytes big-endian
// u32 seq
// u32 timestamp_lo32   (lower 32 bits of 48-bit µs since START_MONITOR)
// u16 frag_idx
// u16 frag_count
// u16 frame_len
// u16 timestamp_hi16   (upper 16 bits of 48-bit µs since START_MONITOR)
const (
	StreamHeaderLen        = 16
	PCAPMagicMicro         = 0xa1b2c3d4 // PCAP standard magic number
	PCAPVersionMaj         = 2
	PCAPVersionMin         = 4
	LinkTypeIEEE80211Radio = 127 // DLT_IEEE802_11_RADIO (RadioTap header)
)

// PCAPWriter writes raw frames to a standard .pcap file
type PCAPWriter struct {
	file *os.File
	mu   sync.Mutex
}

// NewPCAPWriter initializes and writes the global PCAP file header
func NewPCAPWriter(filepath string) (*PCAPWriter, error) {
	f, err := os.Create(filepath)
	if err != nil {
		return nil, fmt.Errorf("create pcap file: %w", err)
	}

	// Write 24-byte Global PCAP Header
	hdr := make([]byte, 24)
	binary.LittleEndian.PutUint32(hdr[0:4], PCAPMagicMicro)
	binary.LittleEndian.PutUint16(hdr[4:6], PCAPVersionMaj)
	binary.LittleEndian.PutUint16(hdr[6:8], PCAPVersionMin)
	binary.LittleEndian.PutUint32(hdr[8:12], 0)                       // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0)                      // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535)                  // snaplen
	binary.LittleEndian.PutUint32(hdr[20:24], LinkTypeIEEE80211Radio) // network / DLT

	if _, err := f.Write(hdr); err != nil {
		f.Close()
		return nil, fmt.Errorf("write pcap header: %w", err)
	}

	return &PCAPWriter{file: f}, nil
}

// WriteFrame appends a captured packet with standard PCAP record header
func (w *PCAPWriter) WriteFrame(data []byte, ts time.Time) error {
	w.mu.Lock()
	defer w.mu.Unlock()

	recHdr := make([]byte, 16)
	binary.LittleEndian.PutUint32(recHdr[0:4], uint32(ts.Unix()))
	binary.LittleEndian.PutUint32(recHdr[4:8], uint32(ts.Nanosecond()/1000)) // microseconds
	binary.LittleEndian.PutUint32(recHdr[8:12], uint32(len(data)))           // caplen
	binary.LittleEndian.PutUint32(recHdr[12:16], uint32(len(data)))          // origlen

	if _, err := w.file.Write(recHdr); err != nil {
		return err
	}
	if _, err := w.file.Write(data); err != nil {
		return err
	}
	return nil
}

// Close closes the file
func (w *PCAPWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file != nil {
		return w.file.Close()
	}
	return nil
}

// FrameReceiver manages the UDP 5555 stream and defragmentation
type FrameReceiver struct {
	conn         *net.UDPConn
	pcapWriter   *PCAPWriter
	closeCh      chan struct{}
	stopped      bool
	mu           sync.Mutex
	captureStart time.Time // set on first packet for timestamp reconstruction
}

// StartStreamReceiver opens UDP listener on streamPort and captures frames
func StartStreamReceiver(port int, pcapDest string, onFrame func(seq uint32, frame []byte)) (*FrameReceiver, error) {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("listen udp stream on :%d: %w", port, err)
	}

	// Buffer socket to prevent frame drop under load
	_ = conn.SetReadBuffer(2 * 1024 * 1024)

	var pw *PCAPWriter
	if pcapDest != "" {
		var err error
		pw, err = NewPCAPWriter(pcapDest)
		if err != nil {
			conn.Close()
			return nil, err
		}
	}

	rcv := &FrameReceiver{
		conn:       conn,
		pcapWriter: pw,
		closeCh:    make(chan struct{}),
	}

	go rcv.readLoop(onFrame)
	return rcv, nil
}

func (r *FrameReceiver) readLoop(onFrame func(seq uint32, frame []byte)) {
	buf := make([]byte, 4096)

	const maxFragSets = 16
	const maxFragCount = 64 // must fit in the uint64 received-mask
	const fragTTL = 100 * time.Millisecond

	type fragEntry struct {
		slots    [][]byte // indexed by fragIdx; nil = not yet received
		received uint64   // bitmask of received fragment indices
		count    uint16
		frameLen uint16
		expires  time.Time
	}
	frags := make(map[uint32]*fragEntry, maxFragSets)
	var dropCount uint64

	for {
		select {
		case <-r.closeCh:
			return
		default:
		}

		_ = r.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
		n, _, err := r.conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-r.closeCh:
				return
			default:
				continue
			}
		}

		if n < StreamHeaderLen {
			continue
		}

		// Evict stale fragment sets
		now := time.Now()
		for s, e := range frags {
			if now.After(e.expires) {
				dropCount++
				delete(frags, s)
			}
		}

		seq := binary.BigEndian.Uint32(buf[0:4])
		tsLo32 := binary.BigEndian.Uint32(buf[4:8])
		fragIdx := binary.BigEndian.Uint16(buf[8:10])
		fragCount := binary.BigEndian.Uint16(buf[10:12])
		frameLen := binary.BigEndian.Uint16(buf[12:14])
		tsHi16 := binary.BigEndian.Uint16(buf[14:16])
		// Reconstruct 48-bit µs timestamp
		tsUS48 := (uint64(tsHi16) << 32) | uint64(tsLo32)
		payload := buf[StreamHeaderLen:n]

		var fullFrame []byte
		if fragCount == 1 {
			fullFrame = make([]byte, len(payload))
			copy(fullFrame, payload)
		} else {
			// Indexed multi-fragment reassembly. Datagrams may arrive out of
			// order or be duplicated, so slot each fragment by fragIdx and
			// emit the frame only once every index is present.
			if fragCount == 0 || fragCount > maxFragCount || fragIdx >= fragCount {
				dropCount++
				continue
			}

			entry, exists := frags[seq]
			if !exists {
				// Evict oldest if at capacity
				if len(frags) >= maxFragSets {
					var oldest uint32
					var oldestTime time.Time
					first := true
					for s, e := range frags {
						if first || e.expires.Before(oldestTime) {
							oldest = s
							oldestTime = e.expires
							first = false
						}
					}
					dropCount++
					delete(frags, oldest)
				}
				entry = &fragEntry{
					slots:    make([][]byte, fragCount),
					count:    fragCount,
					frameLen: frameLen,
					expires:  time.Now().Add(fragTTL),
				}
				frags[seq] = entry
			}

			if entry.count != fragCount || entry.frameLen != frameLen {
				// Inconsistent header for the same sequence: discard the set.
				delete(frags, seq)
				dropCount++
				continue
			}

			if entry.slots[fragIdx] == nil {
				chunk := make([]byte, len(payload))
				copy(chunk, payload)
				entry.slots[fragIdx] = chunk
				entry.received |= uint64(1) << fragIdx
			}
			entry.expires = time.Now().Add(fragTTL) // refresh TTL on activity

			var allReceived uint64
			if entry.count >= 64 {
				allReceived = ^uint64(0)
			} else {
				allReceived = (uint64(1) << entry.count) - 1
			}
			if entry.received != allReceived {
				continue
			}

			total := 0
			for _, s := range entry.slots {
				total += len(s)
			}
			if frameLen > 0 && total < int(frameLen) {
				// Every index arrived but the payload is short of frame_len.
				delete(frags, seq)
				dropCount++
				continue
			}
			fullFrame = make([]byte, 0, total)
			for _, s := range entry.slots {
				fullFrame = append(fullFrame, s...)
			}
			if frameLen > 0 && len(fullFrame) > int(frameLen) {
				fullFrame = fullFrame[:frameLen]
			}
			delete(frags, seq)
		}

		// §2.2: Reconstruct PCAP timestamp from 48-bit µs stream timestamp
		r.mu.Lock()
		if r.captureStart.IsZero() {
			r.captureStart = time.Now()
		}
		pcapTime := r.captureStart.Add(time.Duration(tsUS48) * time.Microsecond)
		r.mu.Unlock()

		if r.pcapWriter != nil {
			_ = r.pcapWriter.WriteFrame(fullFrame, pcapTime)
		}

		if onFrame != nil {
			onFrame(seq, fullFrame)
		}

		_ = dropCount // suppress unused warning if no logging
	}
}

// Close stops receiver and flushes pcap
func (r *FrameReceiver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.stopped {
		return nil
	}
	r.stopped = true
	close(r.closeCh)

	if r.conn != nil {
		r.conn.Close()
	}
	if r.pcapWriter != nil {
		return r.pcapWriter.Close()
	}
	return nil
}
