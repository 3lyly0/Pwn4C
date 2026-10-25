package drone

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// Upgrade issues the UPGRADE command: the drone downloads the image from
// imageURL (a temporary HTTP server on the host), verifies size and SHA-256
// and flashes it with sysupgrade. The drone reboots when the response has
// been delivered — the connection drops right after.
func (c *ControlClient) Upgrade(imageURL string, sizeBytes int64, sha256Hex string) error {
	params := map[string]interface{}{
		"url":    imageURL,
		"size":   sizeBytes,
		"sha256": sha256Hex,
	}
	resp, err := c.SendCommand("UPGRADE", params)
	if err != nil {
		return err
	}
	return okOrError(resp, "UPGRADE")
}

// ComputeImageMeta returns the size and SHA-256 of a local sysupgrade image.
func ComputeImageMeta(path string) (int64, string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, "", err
	}
	sum := sha256.Sum256(data)
	return int64(len(data)), hex.EncodeToString(sum[:]), nil
}

// imageServer is a short-lived HTTP server that serves exactly one file —
// the sysupgrade image the drone pulls during UPGRADE.
type imageServer struct {
	port      int
	requested chan struct{}
	served    chan error
	listener  net.Listener
}

// StartImageServer binds an ephemeral TCP port and serves filePath on any
// GET request. Use IP() and Port() to build the URL handed to the drone.
func StartImageServer(filePath string) (*ImageServerHandle, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return nil, fmt.Errorf("image not found: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("%s is a directory, not a sysupgrade image", filePath)
	}

	l, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		return nil, err
	}

	srv := &imageServer{
		port:      l.Addr().(*net.TCPAddr).Port,
		requested: make(chan struct{}, 1),
		served:    make(chan error, 1),
		listener:  l,
	}
	go srv.serve(filePath)

	return &ImageServerHandle{srv: srv}, nil
}

// ImageServerHandle owns the lifecycle of the temporary image server.
type ImageServerHandle struct {
	srv *imageServer
}

// Port is the ephemeral TCP port the server listens on.
func (h *ImageServerHandle) Port() int { return h.srv.port }

// Requested receives a signal once the drone asked for the image.
func (h *ImageServerHandle) Requested() <-chan struct{} { return h.srv.requested }

// Served receives the transfer outcome once the image download finished
// (or failed).
func (h *ImageServerHandle) Served() <-chan error { return h.srv.served }

// Close shuts the listener down.
func (h *ImageServerHandle) Close() { _ = h.srv.listener.Close() }

func (s *imageServer) serve(filePath string) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()

			_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
			buf := make([]byte, 1024)
			if _, err := c.Read(buf); err != nil && err != io.EOF {
				return
			}

			select {
			case s.requested <- struct{}{}:
			default:
			}

			data, err := os.ReadFile(filePath)
			if err != nil {
				s.served <- err
				return
			}

			_ = c.SetWriteDeadline(time.Now().Add(2 * time.Minute))
			header := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(data))
			if _, err := io.WriteString(c, header); err != nil {
				s.served <- err
				return
			}
			written, err := io.Copy(c, bytes.NewReader(data))
			if err == nil && written != int64(len(data)) {
				err = io.ErrShortWrite
			}
			s.served <- err
		}(conn)
	}
}

// LocalIPFor returns the host IP that routes to targetIP (the address the
// drone will see as the source of host-originated connections).
func LocalIPFor(targetIP string) (string, error) {
	conn, err := net.Dial("udp", net.JoinHostPort(targetIP, "80"))
	if err != nil {
		return "", err
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return "", fmt.Errorf("could not determine local address for %s", targetIP)
	}
	if strings.HasPrefix(addr.IP.String(), "0.0.0.0") {
		return "", fmt.Errorf("could not determine local address for %s", targetIP)
	}
	return addr.IP.String(), nil
}
