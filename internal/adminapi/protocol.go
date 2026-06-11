package adminapi

import (
	"encoding/json"
	"fmt"
	"io"
)

const DefaultSocketPath = "/run/killswitch/admin.sock"

type MessageType string

const (
	MessageTypeConfigRequest  MessageType = "config_request"
	MessageTypeConfig         MessageType = "config"
	MessageTypeSubscribe      MessageType = "subscribe"
	MessageTypeEvent          MessageType = "event"
	MessageTypeMutation       MessageType = "mutation"
	MessageTypeMutationResult MessageType = "mutation_result"
	MessageTypeDebugNotify    MessageType = "debug_notify"
	MessageTypeDebugResult    MessageType = "debug_result"
)

type Envelope struct {
	Type    MessageType     `json:"type"`
	Payload json.RawMessage `json:"payload,omitempty"`
}

type Message interface {
	messageType() MessageType
}

type ConfigRequest struct{}

func (ConfigRequest) messageType() MessageType {
	return MessageTypeConfigRequest
}

type ConfigMessage struct {
	Config CurrentConfig `json:"config"`
}

func (ConfigMessage) messageType() MessageType {
	return MessageTypeConfig
}

type EventType string

const (
	EventTypeConfig       EventType = "config"
	EventTypeInterfaces   EventType = "interfaces"
	EventTypeClients      EventType = "clients"
	EventTypeNotification EventType = "notification"
)

type SubscribeRequest struct {
	EventTypes []EventType `json:"event_types"`
}

func (SubscribeRequest) messageType() MessageType {
	return MessageTypeSubscribe
}

type EventMessage struct {
	EventType    EventType     `json:"event_type"`
	Config       CurrentConfig `json:"config,omitempty"`
	Notification Notification  `json:"notification,omitempty"`
}

func (EventMessage) messageType() MessageType {
	return MessageTypeEvent
}

type NotificationLevel string

const (
	NotificationLevelNormal NotificationLevel = "normal"
	NotificationLevelWarn   NotificationLevel = "warn"
	NotificationLevelError  NotificationLevel = "error"
)

type Notification struct {
	Level  NotificationLevel `json:"level"`
	Text   string            `json:"text"`
	Header string            `json:"header,omitempty"`
}

type DebugNotifyRequest struct {
	Notification Notification `json:"notification"`
}

func (DebugNotifyRequest) messageType() MessageType {
	return MessageTypeDebugNotify
}

type DebugResult struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

func (DebugResult) messageType() MessageType {
	return MessageTypeDebugResult
}

type MutationOperation string

const (
	MutationAdd    MutationOperation = "add"
	MutationRemove MutationOperation = "remove"
	MutationSet    MutationOperation = "set"
)

type MutationRequest struct {
	Operation  MutationOperation `json:"operation"`
	Target     string            `json:"target"`
	Ruleset    string            `json:"ruleset,omitempty"`
	Value      json.RawMessage   `json:"value,omitempty"`
	Values     []string          `json:"values,omitempty"`
	Policy     *AllowRules       `json:"policy,omitempty"`
	RulesetDef *RulesetMutation  `json:"ruleset_def,omitempty"`
}

func (MutationRequest) messageType() MessageType {
	return MessageTypeMutation
}

type MutationResult struct {
	OK      bool          `json:"ok"`
	Changed bool          `json:"changed"`
	Error   string        `json:"error,omitempty"`
	Config  CurrentConfig `json:"config"`
}

func (MutationResult) messageType() MessageType {
	return MessageTypeMutationResult
}

type UnknownMessage struct {
	Type    MessageType
	Payload json.RawMessage
}

func (m UnknownMessage) messageType() MessageType {
	return m.Type
}

type CurrentConfig struct {
	InterfaceTypes          []string       `json:"interface_types,omitempty"`
	InterfaceNames          []string       `json:"interface_names,omitempty"`
	InterfaceRegexps        []string       `json:"interface_regexps,omitempty"`
	IgnoredInterfaceTypes   []string       `json:"ignored_interface_types,omitempty"`
	IgnoredInterfaceNames   []string       `json:"ignored_interface_names,omitempty"`
	IgnoredInterfaceRegexps []string       `json:"ignored_interface_regexps,omitempty"`
	Interfaces              []Interface    `json:"interfaces,omitempty"`
	BasePolicy              AllowRules     `json:"base_policy"`
	EffectivePolicy         AllowRules     `json:"effective_policy"`
	ActiveRuleset           string         `json:"active_ruleset,omitempty"`
	Rulesets                []Ruleset      `json:"rulesets,omitempty"`
	ForceActiveRulesets     []ForceRuleset `json:"force_active_rulesets,omitempty"`
	TemporaryRulesets       []TmpRuleset   `json:"tmp_rulesets,omitempty"`
	Clients                 []ClientInfo   `json:"clients,omitempty"`
	AdminAPI                AdminConfig    `json:"admin_api"`
}

type Interface struct {
	Index      int      `json:"index"`
	Name       string   `json:"name"`
	Type       string   `json:"type"`
	Addrs      []string `json:"addrs,omitempty"`
	Matched    bool     `json:"matched"`
	Killswitch bool     `json:"killswitch"`
}

type ClientInfo struct {
	ID         uint64      `json:"id"`
	Owner      string      `json:"owner"`
	PID        int32       `json:"pid"`
	UID        uint32      `json:"uid"`
	GID        uint32      `json:"gid"`
	EventTypes []EventType `json:"event_types,omitempty"`
}

type AdminConfig struct {
	SocketPath string `json:"socket_path"`
	Debug      bool   `json:"debug"`
}

type AllowRules struct {
	AllowAll       bool     `json:"allow_all"`
	EnableV4       bool     `json:"enable_v4"`
	EnableV6       bool     `json:"enable_v6"`
	AllowedMarks   []string `json:"allowed_marks,omitempty"`
	AllowedPorts   []string `json:"allowed_ports,omitempty"`
	AllowedV4Hosts []string `json:"allowed_v4_hosts,omitempty"`
	AllowedV6Hosts []string `json:"allowed_v6_hosts,omitempty"`
	AllowedV4Pairs []string `json:"allowed_v4_hostports,omitempty"`
	AllowedV6Pairs []string `json:"allowed_v6_hostports,omitempty"`
}

type Ruleset struct {
	Name     string         `json:"name"`
	Active   bool           `json:"active"`
	Disabled bool           `json:"disabled"`
	Priority int            `json:"priority"`
	MatchAll bool           `json:"match_all"`
	Trigger  RulesetTrigger `json:"trigger"`
	Policy   AllowRules     `json:"policy"`
}

type TmpRuleset struct {
	Client string     `json:"client"`
	Policy AllowRules `json:"policy"`
}

type ForceRuleset struct {
	Name    string   `json:"name"`
	Clients []string `json:"clients,omitempty"`
}

type RulesetMutation struct {
	Disabled bool           `json:"disabled"`
	Priority int            `json:"priority"`
	MatchAll bool           `json:"match_all"`
	Trigger  RulesetTrigger `json:"trigger"`
	Policy   AllowRules     `json:"policy"`
}

type RulesetTrigger struct {
	InterfaceTypes   []string `json:"interface_types,omitempty"`
	InterfaceNames   []string `json:"interface_names,omitempty"`
	InterfaceRegexps []string `json:"interface_regexps,omitempty"`
	IPAddrs          []string `json:"ip_addrs,omitempty"`
}

func WriteMessage(encoder *json.Encoder, msg Message) error {
	payload, err := messagePayload(msg)
	if err != nil {
		return err
	}
	return encoder.Encode(Envelope{
		Type:    msg.messageType(),
		Payload: payload,
	})
}

func ReadMessage(decoder *json.Decoder) (Message, error) {
	var envelope Envelope
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}

	switch envelope.Type {
	case MessageTypeConfigRequest:
		var msg ConfigRequest
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeConfig:
		var msg ConfigMessage
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeSubscribe:
		var msg SubscribeRequest
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeEvent:
		var msg EventMessage
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeMutation:
		var msg MutationRequest
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeMutationResult:
		var msg MutationResult
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeDebugNotify:
		var msg DebugNotifyRequest
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	case MessageTypeDebugResult:
		var msg DebugResult
		if err := decodePayload(envelope.Payload, &msg); err != nil {
			return nil, err
		}
		return msg, nil
	default:
		return UnknownMessage(envelope), nil
	}
}

func messagePayload(msg Message) (json.RawMessage, error) {
	switch typed := msg.(type) {
	case ConfigRequest:
		return json.Marshal(typed)
	case *ConfigRequest:
		return json.Marshal(typed)
	case ConfigMessage:
		return json.Marshal(typed)
	case *ConfigMessage:
		return json.Marshal(typed)
	case SubscribeRequest:
		return json.Marshal(typed)
	case *SubscribeRequest:
		return json.Marshal(typed)
	case EventMessage:
		return json.Marshal(typed)
	case *EventMessage:
		return json.Marshal(typed)
	case MutationRequest:
		return json.Marshal(typed)
	case *MutationRequest:
		return json.Marshal(typed)
	case MutationResult:
		return json.Marshal(typed)
	case *MutationResult:
		return json.Marshal(typed)
	case DebugNotifyRequest:
		return json.Marshal(typed)
	case *DebugNotifyRequest:
		return json.Marshal(typed)
	case DebugResult:
		return json.Marshal(typed)
	case *DebugResult:
		return json.Marshal(typed)
	default:
		return nil, fmt.Errorf("unsupported admin API message type %T", msg)
	}
}

func decodePayload(payload json.RawMessage, dst any) error {
	if len(payload) == 0 {
		payload = []byte("{}")
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return fmt.Errorf("decode admin API payload: %w", err)
	}
	return nil
}

func IsEOF(err error) bool {
	return err == io.EOF
}
