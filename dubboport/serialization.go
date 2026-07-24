package dubboport

import "fmt"

// SerializationType represents Dubbo serialization types.
type SerializationType byte

const (
	SerializationHessian2       SerializationType = 0
	SerializationJava           SerializationType = 1
	SerializationCompactedJava  SerializationType = 2
	SerializationNativeJava     SerializationType = 3
	SerializationFastJson       SerializationType = 4
	SerializationHessian1       SerializationType = 5
	SerializationKryo           SerializationType = 6
	SerializationFst            SerializationType = 7
	SerializationJson           SerializationType = 8
	SerializationMsgPack        SerializationType = 9
	SerializationProtobuf       SerializationType = 10
	SerializationProtobufJson   SerializationType = 11
)

var serializationNames = map[SerializationType]string{
	SerializationHessian2:      "hessian2",
	SerializationJava:          "java",
	SerializationCompactedJava: "compactedjava",
	SerializationNativeJava:    "nativejava",
	SerializationFastJson:      "fastjson",
	SerializationHessian1:      "hessian1",
	SerializationKryo:          "kryo",
	SerializationFst:           "fst",
	SerializationJson:          "json",
	SerializationMsgPack:       "msgpack",
	SerializationProtobuf:      "protobuf",
	SerializationProtobufJson:  "protobuf-json",
}

func (s SerializationType) String() string {
	if name, ok := serializationNames[s]; ok {
		return name
	}
	return fmt.Sprintf("unknown(%d)", s)
}

// Status codes for Dubbo response.
const (
	StatusOK                byte = 20
	StatusClientTimeout     byte = 30
	StatusServerTimeout     byte = 31
	StatusBadRequest        byte = 40
	StatusBadResponse       byte = 50
	StatusServiceNotFound   byte = 60
	StatusServiceError      byte = 70
	StatusServerError       byte = 80
	StatusClientError       byte = 90
	StatusServerThreadpoolExhausted byte = 100
)

var statusNames = map[byte]string{
	StatusOK:                "OK",
	StatusClientTimeout:     "CLIENT_TIMEOUT",
	StatusServerTimeout:     "SERVER_TIMEOUT",
	StatusBadRequest:        "BAD_REQUEST",
	StatusBadResponse:       "BAD_RESPONSE",
	StatusServiceNotFound:   "SERVICE_NOT_FOUND",
	StatusServiceError:      "SERVICE_ERROR",
	StatusServerError:       "SERVER_ERROR",
	StatusClientError:       "CLIENT_ERROR",
	StatusServerThreadpoolExhausted: "SERVER_THREADPOOL_EXHAUSTED",
}

// StatusString returns human-readable status string.
func StatusString(status byte) string {
	if name, ok := statusNames[status]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN(%d)", status)
}
