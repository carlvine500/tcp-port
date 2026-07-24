package rocketmqport

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
)

// RocketMQ Remoting protocol frame format:
//
//	frame length  (4 bytes, big-endian) — total length including this field
//	header length (4 bytes, big-endian) — length of header JSON (including this 4-byte field)
//	header data   (variable)            — JSON serialized
//	body          (variable, optional)
//
// Min frame: 4 (frame length) + 4 (header length) + 2 ("{}") = 10 bytes
// Max frame: 100 MB (practical limit)

const (
	RocketMQMinFrameSize = 10
	RocketMQMaxFrameSize = 100 * 1024 * 1024 // 100 MB
)

// RemotingCommand represents a decoded RocketMQ remoting command.
type RemotingCommand struct {
	// Raw frame data
	FrameLength  uint32
	HeaderLength uint32
	HeaderJSON   string
	Body         []byte

	// Parsed header fields
	Code      int    `json:"code"`
	Language  string `json:"language"`
	Version   int    `json:"version"`
	Opaque    int    `json:"opaque"`
	Flag      int    `json:"flag"`
	Remark    string `json:"remark"`
	ExtFields map[string]string `json:"extFields"`

	// Parsed body info (best-effort)
	BodyPreview string
}

// Request codes (common RocketMQ request types)
var requestCodeNames = map[int]string{
	10:   "SEND_MESSAGE",
	11:   "PULL_MESSAGE",
	12:   "QUERY_MESSAGE",
	13:   "QUERY_BROKER_OFFSET",
	14:   "QUERY_CONSUMER_OFFSET",
	15:   "UPDATE_CONSUMER_OFFSET",
	16:   "UPDATE_AND_CREATE_TOPIC",
	17:   "GET_ALL_TOPIC_CONFIG",
	18:   "GET_TOPIC_CONFIG_LIST",
	19:   "GET_TOPIC_NAME_LIST",
	20:   "UPDATE_BROKER_CONFIG",
	21:   "GET_BROKER_CONFIG",
	22:   "TRIGGER_DELETE_FILES",
	23:   "GET_BROKER_RUNTIME_INFO",
	24:   "SEARCH_OFFSET_BY_TIMESTAMP",
	25:   "GET_MAX_OFFSET",
	26:   "GET_MIN_OFFSET",
	27:   "GET_EARLIEST_MSG_STORETIME",
	28:   "QUERY_MESSAGE_BY_KEY",
	29:   "QUERY_MESSAGE_BY_UNIQUE_KEY",
	30:   "PULL_KV_CONFIG",
	31:   "QUERY_DATA_VERSION",
	32:   "UPDATE_AND_CREATE_SUBSCRIPTIONGROUP",
	33:   "GET_ALL_SUBSCRIPTIONGROUP_CONFIG",
	34:   "GET_TOPIC_STATS_INFO",
	35:   "GET_CONSUMER_LIST_BY_GROUP",
	36:   "GET_SUBSCRIPTIONGROUP_CONFIG",
	37:   "QUERY_CONSUME_TIME_SPAN",
	38:   "GET_BROKER_CONSUME_STATS",
	39:   "INVOKE_BROKER_TO_RESET_OFFSET",
	40:   "GET_CONSUMER_RUNNING_INFO",
	41:   "QUERY_CORRECTION_OFFSET",
	42:   "CONSUME_MESSAGE_DIRECTLY",
	43:   "PULL_MESSAGE",
	44:   "QUERY_CONSUMER_OFFSET",
	45:   "VIEW_MESSAGE_BY_ID",
	46:   "QUERY_MESSAGES",
	47:   "GET_HOME_TOPIC_ROUTE_INFO",
	48:   "GET_MESSAGE_STORE_TIME",
	49:   "QUERY_BROKER_OFFSET",
	50:   "HEART_BEAT",
	51:   "UNREGISTER_CLIENT",
	52:   "REGISTER_CLIENT",
	53:   "CONSUMER_SEND_MSG_BACK",
	54:   "END_TRANSACTION",
	55:   "GET_CONSUMER_LIST_BY_GROUP",
	56:   "CHECK_TRANSACTION_STATE",
	57:   "NOTIFY_CONSUMER_IDS_CHANGED",
	58:   "LOCK_BATCH_MQ",
	59:   "UNLOCK_BATCH_MQ",
	60:   "GET_ALL_CONSUMER_OFFSET",
	61:   "GET_ALL_DELAY_OFFSET",
	62:   "PUT_KV_CONFIG",
	63:   "DELETE_KV_CONFIG",
	64:   "REGISTER_FILTER_SERVER",
	65:   "REGISTER_MESSAGE_FILTER_CLASS",
	66:   "QUERY_TOPIC_CONSUME_BY_WHO",
	67:   "DELETE_TOPIC_IN_BROKER",
	68:   "DELETE_SUBSCRIPTIONGROUP",
	69:   "GET_CONSUME_STATS",
	70:   "GET_PRODUCER_CONNECTION_LIST",
	71:   "GET_CONSUMER_CONNECTION_LIST",
	72:   "VC_CHANNEL",
	73:   "GET_PRODUCER_CONNECTION_LIST",
	74:   "GET_CONSUMER_CONNECTION_LIST",
	100:  "REGISTER_BROKER",
	101:  "UNREGISTER_BROKER",
	102:  "GET_ROUTEINTO_BY_TOPIC",
	103:  "GET_BROKER_CLUSTER_INFO",
	104:  "WIPE_WRITE_PERM_OF_BROKER",
	105:  "GET_ALL_TOPIC_LIST_FROM_NAMESERVER",
	106:  "DELETE_TOPIC_IN_NAMESRV",
	107:  "REGISTER_TOPIC_IN_NAMESRV",
	108:  "GET_KVLIST_BY_NAMESPACE",
	109:  "GET_TOPICS_BY_CLUSTER",
	110:  "GET_SYSTEM_TOPIC_LIST_FROM_NS",
	111:  "GET_UNIT_TOPIC_LIST",
	112:  "GET_HAS_UNIT_SUB_TOPIC_LIST",
	113:  "GET_HAS_UNIT_SUB_UNUNIT_TOPIC_LIST",
	114:  "UPDATE_NAMESRV_CONFIG",
	115:  "GET_NAMESRV_CONFIG",
	201:  "ACTIVATE_NAMESERVER",
	202:  "DEACTIVATE_NAMESERVER",
	203:  "BROKER_HEARTBEAT",
	900:  "REGISTER_MESSAGE_FILTER_CLASS",
}

// RequestCodeName returns human-readable name for a request code.
func RequestCodeName(code int) string {
	if name, ok := requestCodeNames[code]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", code)
}

// ReadRemotingCommand reads a RocketMQ remoting command from reader.
func ReadRemotingCommand(r io.Reader) (*RemotingCommand, error) {
	// Read frame length (4 bytes)
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf)

	if frameLen < RocketMQMinFrameSize || frameLen > RocketMQMaxFrameSize {
		return nil, fmt.Errorf("invalid frame length: %d", frameLen)
	}

	// Read remaining frame data
	remaining := make([]byte, frameLen-4)
	if _, err := io.ReadFull(r, remaining); err != nil {
		return nil, err
	}

	// Parse header length (next 4 bytes of remaining)
	if len(remaining) < 4 {
		return nil, fmt.Errorf("frame too short for header length")
	}
	headerLen := binary.BigEndian.Uint32(remaining[0:4])

	if headerLen < 4 || int(headerLen) > len(remaining)+4 {
		return nil, fmt.Errorf("invalid header length: %d", headerLen)
	}

	// Extract header JSON
	headerEnd := headerLen
	headerJSON := string(remaining[4:headerEnd])

	// Extract body (if any)
	var body []byte
	if int(frameLen) > int(headerEnd)+4 {
		body = remaining[headerEnd:]
	}

	cmd := &RemotingCommand{
		FrameLength:  frameLen,
		HeaderLength: headerLen,
		HeaderJSON:   headerJSON,
		Body:         body,
	}

	// Parse header JSON
	if err := json.Unmarshal([]byte(headerJSON), &cmd); err == nil {
		// Parsed successfully
	}

	// Build body preview
	if len(body) > 0 {
		if len(body) > 200 {
			cmd.BodyPreview = fmt.Sprintf("%x...", body[:200])
		} else {
			cmd.BodyPreview = fmt.Sprintf("%x", body)
		}
	}

	return cmd, nil
}

// DetectRocketMQ checks if data looks like RocketMQ remoting protocol.
func DetectRocketMQ(data []byte) bool {
	if len(data) < 4 {
		return false
	}
	frameLen := binary.BigEndian.Uint32(data[0:4])
	if frameLen < RocketMQMinFrameSize || frameLen > RocketMQMaxFrameSize {
		return false
	}
	// Further check: try to parse header as JSON
	if len(data) >= 8 {
		headerLen := binary.BigEndian.Uint32(data[4:8])
		if headerLen >= 4 && headerLen <= frameLen {
			// Try to detect JSON header
			if int(headerLen) <= len(data)-8 {
				headerStart := 8
				headerEnd := 8 + int(headerLen) - 4
				if headerEnd <= len(data) {
					header := data[headerStart:headerEnd]
					return json.Valid(header)
				}
			}
		}
	}
	return frameLen >= RocketMQMinFrameSize && frameLen <= RocketMQMaxFrameSize
}
