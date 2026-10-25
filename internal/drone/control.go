package drone

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

// DefaultPSK holds the global pre-shared key configured via --psk or PWN4C_PSK.
var DefaultPSK string

// ControlClient manages the TCP control connection with pwn4cd
type ControlClient struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
	msgSeq int

	// OnEvent, when set, receives unsolicited daemon events (e.g.
	// BUFFER_OVERFLOW). When nil they are logged to stderr.
	OnEvent func(AsyncEvent)
}

// AsyncEvent is an unsolicited newline-delimited JSON event pushed by the
// daemon on the control channel (identifiable by a non-empty "event" field
// and a null "id").
type AsyncEvent struct {
	Event string          `json:"event"`
	Data  json.RawMessage `json:"data"`
}

// CommandRequest represents an outgoing JSON command
type CommandRequest struct {
	ID      string                 `json:"id"`
	Command string                 `json:"command"`
	Params  map[string]interface{} `json:"params,omitempty"`
}

// StatusData represents telemetry payload in GET_STATUS
type StatusData struct {
	State           string `json:"state"`
	Channel         int    `json:"channel"`
	MonitorActive   bool   `json:"monitor_active"`
	TxQueueDepth    int    `json:"tx_queue_depth"`
	TxQueueMax      int    `json:"tx_queue_max"`
	UptimeSeconds   int    `json:"uptime_seconds"`
	CPUTempCelsius  int    `json:"cpu_temp_celsius"`
	FreeRAMBytes    int64  `json:"free_ram_bytes"`
	FirmwareVersion string `json:"firmware_version"`
	DroneID         string `json:"drone_id"`
	RxFrames        uint64 `json:"rx_frames"`
	TxFrames        uint64 `json:"tx_frames"`
	RingOverruns    uint64 `json:"ring_overruns"`
	InjectFailures  uint64 `json:"inject_failures"`
	KernelDrops     uint32 `json:"kernel_drops"`
	IfaceRecoveries uint64 `json:"iface_recoveries"`
}

// DiagnosticsData represents system health in GET_DIAGNOSTICS
type DiagnosticsData struct {
	KernelVersion  string `json:"kernel_version"`
	UptimeSeconds  int    `json:"uptime_seconds"`
	LoadAverageRaw string `json:"load_average_raw"`
	Memory         struct {
		FreeBytes int64 `json:"free_bytes"`
	} `json:"memory"`
	Wireless struct {
		Interface string `json:"interface"`
		Driver    string `json:"driver"`
		Channel   int    `json:"channel"`
	} `json:"wireless"`
}

// ControlError details
type ControlError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// BaseResponse represents standard response from drone
type BaseResponse struct {
	ID     string          `json:"id"`
	Status string          `json:"status"` // "ok" or "error"
	Data   json.RawMessage `json:"data,omitempty"`
	Error  *ControlError   `json:"error,omitempty"`
}

// ConnectControl dials the drone's TCP control port and performs PSK
// challenge-response authentication if DefaultPSK or PWN4C_PSK is configured.
func ConnectControl(droneAddr string, timeout time.Duration) (*ControlClient, error) {
	if !strings.Contains(droneAddr, ":") {
		droneAddr = fmt.Sprintf("%s:%d", droneAddr, DefaultControlPort)
	}

	conn, err := net.DialTimeout("tcp", droneAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", droneAddr, err)
	}

	client := &ControlClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}

	psk := DefaultPSK
	if psk == "" {
		psk = os.Getenv("PWN4C_PSK")
	}
	if psk != "" {
		if err := client.Authenticate(psk); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("authentication failed: %w", err)
		}
	}

	return client, nil
}

// Authenticate performs the HMAC-SHA256 challenge-response handshake (§4.1)
func (c *ControlClient) Authenticate(psk string) error {
	resp, err := c.SendCommand("GET_CHALLENGE", nil)
	if err != nil {
		return fmt.Errorf("GET_CHALLENGE: %w", err)
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to request challenge")
	}

	var chal struct {
		Nonce        string `json:"nonce"`
		AuthRequired bool   `json:"auth_required"`
	}
	if err := json.Unmarshal(resp.Data, &chal); err != nil {
		return fmt.Errorf("unmarshal challenge: %w", err)
	}
	if chal.Nonce == "" {
		return fmt.Errorf("empty challenge nonce returned by drone")
	}

	mac := hmac.New(sha256.New, []byte(psk))
	mac.Write([]byte(chal.Nonce))
	sig := hex.EncodeToString(mac.Sum(nil))

	authResp, err := c.SendCommand("AUTH", map[string]interface{}{
		"hmac": sig,
	})
	if err != nil {
		return fmt.Errorf("AUTH: %w", err)
	}
	if strings.ToLower(authResp.Status) != "ok" {
		if authResp.Error != nil {
			return fmt.Errorf("%s: %s", authResp.Error.Code, authResp.Error.Message)
		}
		return fmt.Errorf("HMAC rejected by drone")
	}
	return nil
}

// Close closes the control connection
func (c *ControlClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// SendCommand sends a command and returns the JSON response
func (c *ControlClient) SendCommand(cmd string, params map[string]interface{}) (*BaseResponse, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.msgSeq++
	req := CommandRequest{
		ID:      fmt.Sprintf("cmd-%d", c.msgSeq),
		Command: cmd,
		Params:  params,
	}

	payload, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal command: %w", err)
	}

	// Delimited with newline
	payload = append(payload, '\n')
	if _, err := c.conn.Write(payload); err != nil {
		return nil, fmt.Errorf("write command: %w", err)
	}

	// Read lines until the response matching req.ID arrives. The daemon may
	// interleave unsolicited events (e.g. BUFFER_OVERFLOW) with command
	// replies; those must be consumed and skipped rather than mistaken for
	// the reply, which would desynchronize the stream by one message.
	for {
		line, err := c.reader.ReadBytes('\n')
		if err != nil {
			return nil, fmt.Errorf("read response: %w", err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		var envelope struct {
			ID     json.RawMessage `json:"id"`
			Event  string          `json:"event"`
			Status string          `json:"status"`
		}
		if err := json.Unmarshal(line, &envelope); err != nil {
			return nil, fmt.Errorf("unmarshal response (%s): %w", string(line), err)
		}

		if envelope.Event != "" {
			var ev AsyncEvent
			if err := json.Unmarshal(line, &ev); err == nil {
				if c.OnEvent != nil {
					c.OnEvent(ev)
				} else {
					fmt.Fprintf(os.Stderr, "[drone] event %s: %s\n",
						ev.Event, string(ev.Data))
				}
			}
			continue
		}

		// Not a command response (no status): skip defensively.
		if envelope.Status == "" {
			continue
		}

		var resp BaseResponse
		if err := json.Unmarshal(line, &resp); err != nil {
			return nil, fmt.Errorf("unmarshal response (%s): %w", string(line), err)
		}
		if resp.ID != req.ID {
			// Stale reply for an earlier request; keep waiting for ours.
			continue
		}
		return &resp, nil
	}
}

// GetStatus queries current drone telemetry
func (c *ControlClient) GetStatus() (*StatusData, error) {
	resp, err := c.SendCommand("GET_STATUS", nil)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("status error")
	}

	var status StatusData
	if err := json.Unmarshal(resp.Data, &status); err != nil {
		return nil, fmt.Errorf("unmarshal status data: %w", err)
	}
	return &status, nil
}

// GetDiagnostics queries kernel & hardware diagnostics
func (c *ControlClient) GetDiagnostics() (*DiagnosticsData, error) {
	resp, err := c.SendCommand("GET_DIAGNOSTICS", nil)
	if err != nil {
		return nil, err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return nil, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return nil, fmt.Errorf("diagnostics error")
	}

	var diag DiagnosticsData
	if err := json.Unmarshal(resp.Data, &diag); err != nil {
		return nil, fmt.Errorf("unmarshal diagnostics data: %w", err)
	}
	return &diag, nil
}

// StartMonitor commands the drone to begin 802.11 monitor mode on channel
func (c *ControlClient) StartMonitor(channel int) error {
	params := map[string]interface{}{
		"channel": channel,
	}
	resp, err := c.SendCommand("START_MONITOR", params)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to start monitor")
	}
	return nil
}

// StopMonitor commands the drone to stop monitor mode
func (c *ControlClient) StopMonitor() error {
	resp, err := c.SendCommand("STOP_MONITOR", nil)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to stop monitor")
	}
	return nil
}

// SetChannel switches current monitor channel
func (c *ControlClient) SetChannel(channel int) error {
	params := map[string]interface{}{
		"channel": channel,
	}
	resp, err := c.SendCommand("SET_CHANNEL", params)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to set channel")
	}
	return nil
}

// SetTxPower adjusts radio transmission power in dBm
func (c *ControlClient) SetTxPower(powerDbm int) error {
	params := map[string]interface{}{
		"power_dbm": powerDbm,
	}
	resp, err := c.SendCommand("SET_TX_POWER", params)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to set tx power")
	}
	return nil
}

// RestoreNormal exits monitor mode and restores standard managed Wi-Fi
func (c *ControlClient) RestoreNormal() error {
	resp, err := c.SendCommand("RESTORE_NORMAL", nil)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to restore normal mode")
	}
	return nil
}

// SendInjection transmits a raw 802.11 frame with radiotap header on the
// active monitor channel. It returns how many frames were transmitted
// immediately, how many are still queued in the drone's paced TX ring, and
// how many were dropped because the ring was full. Queued frames leave the
// air over the next interval_ms milliseconds.
func (c *ControlClient) SendInjection(frameHex string, count int, intervalMs int) (sent int, queued int, failed int, err error) {
	params := map[string]interface{}{
		"frame_hex":   frameHex,
		"count":       count,
		"interval_ms": intervalMs,
	}
	resp, err := c.SendCommand("SEND_INJECTION", params)
	if err != nil {
		return 0, 0, 0, err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return 0, 0, 0, fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return 0, 0, 0, fmt.Errorf("failed to inject frame")
	}

	var data struct {
		FramesSent   int `json:"frames_sent"`
		FramesQueued int `json:"frames_queued"`
		FramesFailed int `json:"frames_failed"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return 0, 0, 0, fmt.Errorf("unmarshal injection result: %w", err)
	}
	return data.FramesSent, data.FramesQueued, data.FramesFailed, nil
}

// SetMAC updates the monitor MAC address (or randomizes if empty)
func (c *ControlClient) SetMAC(mac string) (string, error) {
	params := map[string]interface{}{}
	if mac != "" {
		params["mac"] = mac
	}
	resp, err := c.SendCommand("SET_MAC", params)
	if err != nil {
		return "", err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return "", fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return "", fmt.Errorf("failed to set MAC")
	}

	var data struct {
		MAC string `json:"mac"`
	}
	if err := json.Unmarshal(resp.Data, &data); err != nil {
		return "", fmt.Errorf("unmarshal set_mac result: %w", err)
	}
	return data.MAC, nil
}

// Reboot triggers a hardware reboot of the drone
func (c *ControlClient) Reboot() error {
	resp, err := c.SendCommand("REBOOT", nil)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to reboot drone")
	}
	return nil
}

// StartHop commands the drone to autonomously hop across channels with dwellMs
func (c *ControlClient) StartHop(channels []int, dwellMs int) error {
	params := map[string]interface{}{
		"channels": channels,
		"dwell_ms": dwellMs,
	}
	resp, err := c.SendCommand("HOP_START", params)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to start channel hopping")
	}
	return nil
}

// StopHop commands the drone to stop autonomous channel hopping
func (c *ControlClient) StopHop() error {
	resp, err := c.SendCommand("HOP_STOP", nil)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to stop channel hopping")
	}
	return nil
}

// SetFilter configures classic BPF frame filtering (mgmt_only and/or BSSID)
func (c *ControlClient) SetFilter(mgmtOnly bool, bssid string) error {
	params := map[string]interface{}{
		"mgmt_only": mgmtOnly,
	}
	if bssid != "" {
		params["bssid"] = bssid
	}
	resp, err := c.SendCommand("SET_FILTER", params)
	if err != nil {
		return err
	}
	if strings.ToLower(resp.Status) != "ok" {
		if resp.Error != nil {
			return fmt.Errorf("%s: %s", resp.Error.Code, resp.Error.Message)
		}
		return fmt.Errorf("failed to set filter")
	}
	return nil
}
