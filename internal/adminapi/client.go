package adminapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
)

type Client struct {
	conn    net.Conn
	encoder *json.Encoder
	decoder *json.Decoder
}

func DialUnix(ctx context.Context, socketPath string) (*Client, error) {
	var dialer net.Dialer
	conn, err := dialer.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to admin API socket %s: %w", socketPath, err)
	}
	return NewClient(conn), nil
}

func NewClient(conn net.Conn) *Client {
	return &Client{
		conn:    conn,
		encoder: json.NewEncoder(conn),
		decoder: json.NewDecoder(conn),
	}
}

func (c *Client) Close() error {
	return c.conn.Close()
}

func (c *Client) Send(msg Message) error {
	if err := WriteMessage(c.encoder, msg); err != nil {
		return fmt.Errorf("write admin API message: %w", err)
	}
	return nil
}

func (c *Client) Receive() (Message, error) {
	msg, err := ReadMessage(c.decoder)
	if err != nil {
		return nil, err
	}
	return msg, nil
}

func (c *Client) RequestConfig() error {
	return c.Send(ConfigRequest{})
}

func (c *Client) WaitForConfig() (CurrentConfig, error) {
	for {
		msg, err := c.Receive()
		if err != nil {
			if IsEOF(err) {
				return CurrentConfig{}, errors.New("connection closed before config was received")
			}
			return CurrentConfig{}, fmt.Errorf("read admin API message: %w", err)
		}
		if cfg, ok := msg.(ConfigMessage); ok {
			return cfg.Config, nil
		}
	}
}

func (c *Client) Mutate(req MutationRequest) (MutationResult, error) {
	if err := c.Send(req); err != nil {
		return MutationResult{}, err
	}
	return c.WaitForMutationResult()
}

func (c *Client) WaitForMutationResult() (MutationResult, error) {
	for {
		msg, err := c.Receive()
		if err != nil {
			if IsEOF(err) {
				return MutationResult{}, errors.New("connection closed before mutation result was received")
			}
			return MutationResult{}, fmt.Errorf("read admin API message: %w", err)
		}
		if result, ok := msg.(MutationResult); ok {
			return result, nil
		}
	}
}
