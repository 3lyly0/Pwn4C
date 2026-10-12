package drone

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ControlClient manages the TCP control connection with pwn4cd
type ControlClient struct {
	conn   net.Conn
	reader *bufio.Reader
	mu     sync.Mutex
	msgSeq int
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

// ConnectControl dials the drone's TCP control port
func ConnectControl(droneAddr string, timeout time.Duration) (*ControlClient, error) {
	if !strings.Contains(droneAddr, ":") {
		droneAddr = fmt.Sprintf("%s:%d", droneAddr, DefaultControlPort)
	}

	conn, err := net.DialTimeout("tcp", droneAddr, timeout)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", droneAddr, err)
	}

	return &ControlClient{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}, nil
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

	// Read line response
	line, err := c.reader.ReadBytes('\n')
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	var resp BaseResponse
	if err := json.Unmarshal(line, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal response (%s): %w", string(line), err)
	}

	return &resp, nil
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
