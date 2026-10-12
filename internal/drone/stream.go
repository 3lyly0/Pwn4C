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
// u32 timestamp_us
// u16 frag_idx
// u16 frag_count
// u16 frame_len
// u16 reserved
const (
	StreamHeaderLen = 16
	PCAPMagicMicro  = 0xa1b2c3d4 // PCAP standard magic number
	PCAPVersionMaj  = 2
	PCAPVersionMin  = 4
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
	binary.LittleEndian.PutUint32(hdr[8:12], 0) // thiszone
	binary.LittleEndian.PutUint32(hdr[12:16], 0) // sigfigs
	binary.LittleEndian.PutUint32(hdr[16:20], 65535) // snaplen
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
	conn       *net.UDPConn
	pcapWriter *PCAPWriter
	closeCh    chan struct{}
	stopped    bool
	mu         sync.Mutex
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
	// defragmentation map: seq -> buffer
	fragments := make(map[uint32][]byte)

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

		seq := binary.BigEndian.Uint32(buf[0:4])
		// tsUS := binary.BigEndian.Uint32(buf[4:8])
		fragIdx := binary.BigEndian.Uint16(buf[8:10])
		fragCount := binary.BigEndian.Uint16(buf[10:12])
		frameLen := binary.BigEndian.Uint16(buf[12:14])
		payload := buf[StreamHeaderLen:n]

		var fullFrame []byte
		if fragCount == 1 {
			fullFrame = make([]byte, len(payload))
			copy(fullFrame, payload)
		} else {
			// Multi-fragment reassembly
			curr, exists := fragments[seq]
			if !exists {
				curr = make([]byte, 0, frameLen)
			}
			curr = append(curr, payload...)
			if fragIdx == fragCount-1 || len(curr) >= int(frameLen) {
				fullFrame = curr
				delete(fragments, seq)
			} else {
				fragments[seq] = curr
				continue
			}
		}

		now := time.Now()
		if r.pcapWriter != nil {
			_ = r.pcapWriter.WriteFrame(fullFrame, now)
		}

		if onFrame != nil {
			onFrame(seq, fullFrame)
		}
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
