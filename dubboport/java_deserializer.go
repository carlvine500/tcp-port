package dubboport

import (
	"encoding/binary"
	"fmt"
	"math"
)

// Java Object Serialization Stream Protocol constants.
// Reference: https://docs.oracle.com/javase/8/docs/platform/serialization/spec/protocol.html
const (
	_streamMagic   uint16 = 0xACED
	_streamVersion uint16 = 0x0005

	_tcNull           byte = 0x70
	_tcReference      byte = 0x71
	_tcClassDesc      byte = 0x72
	_tcObject         byte = 0x73
	_tcString         byte = 0x74
	_tcArray          byte = 0x75
	_tcClass          byte = 0x76
	_tcBlockData      byte = 0x77
	_tcEndBlockData   byte = 0x78
	_tcReset          byte = 0x79
	_tcBlockDataLong  byte = 0x7A
	_tcException      byte = 0x7B
	_tcLongString     byte = 0x7C
	_tcProxyClassDesc byte = 0x7D
	_tcEnum           byte = 0x7E

	// Class descriptor flags
	_scSerializable   byte = 0x02
	_scExternalizable byte = 0x04
	_scWriteMethod    byte = 0x01
	_scBlockData      byte = 0x08
)

// classDescInfo holds parsed class descriptor data with a link to the
// super class, forming a chain from most-derived to base class.
type classDescInfo struct {
	className string
	flags     byte
	fields    []javaFieldInfo
	super     *classDescInfo
}

// javaFieldInfo describes a single field in a Java class descriptor.
type javaFieldInfo struct {
	typeCode   byte
	name       string
	className1 string // for '[' and 'L' type codes
}

// javaDeserializer parses Java Object Serialization Stream Protocol data.
type javaDeserializer struct {
	data    []byte
	pos     int
	handles []interface{}
}

// deserializeJavaArgs attempts to parse Java serialization stream data
// and extract argument values as a flat map.
//
// The data may optionally start with STREAM_MAGIC + STREAM_VERSION (4 bytes).
// Multiple top-level objects are merged into a single result map.
//
// Returns nil and an error if nothing could be parsed.
func deserializeJavaArgs(data []byte) (map[string]interface{}, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("empty data")
	}

	d := &javaDeserializer{
		data: data,
	}

	// Skip optional STREAM_MAGIC + VERSION header
	if len(data) >= 4 {
		magic := binary.BigEndian.Uint16(data[0:2])
		version := binary.BigEndian.Uint16(data[2:4])
		if magic == _streamMagic && version == _streamVersion {
			d.pos = 4
		}
	}

	result := make(map[string]interface{})
	for d.pos < len(d.data) {
		if d.pos >= len(d.data) {
			break
		}
		tc := d.data[d.pos]

		// Skip blockdata terminators and stream resets
		if tc == _tcEndBlockData {
			d.pos++
			continue
		}
		if tc == _tcReset {
			d.pos++
			d.handles = nil
			continue
		}

		val, err := d.readContent()
		if err != nil {
			// Stop on parse error — return what we have so far
			break
		}
		if val == nil {
			continue
		}
		if m, ok := val.(map[string]interface{}); ok {
			for k, v := range m {
				if _, exists := result[k]; !exists {
					result[k] = v
				}
			}
		}
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no parseable objects found")
	}
	return result, nil
}

// readContent reads and returns the next content element.
func (d *javaDeserializer) readContent() (interface{}, error) {
	if d.pos >= len(d.data) {
		return nil, fmt.Errorf("unexpected end of data at pos %d", d.pos)
	}

	tc := d.data[d.pos]
	switch tc {
	case _tcNull:
		d.pos++
		return nil, nil
	case _tcReference:
		return d.readReference()
	case _tcObject:
		return d.readObject()
	case _tcString:
		return d.readString()
	case _tcLongString:
		return d.readLongString()
	case _tcArray:
		return d.readArray()
	case _tcEnum:
		return d.readEnum()
	case _tcClass:
		return d.readClass()
	case _tcBlockData, _tcBlockDataLong:
		return d.skipBlockData()
	case _tcException:
		return nil, fmt.Errorf("TC_EXCEPTION at pos %d not supported", d.pos)
	case _tcProxyClassDesc:
		return nil, fmt.Errorf("TC_PROXYCLASSDESC at pos %d not supported", d.pos)
	default:
		return nil, fmt.Errorf("unknown type code 0x%02x at pos %d", tc, d.pos)
	}
}

// readObject parses a TC_OBJECT element and returns a flat field→value map.
func (d *javaDeserializer) readObject() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcObject {
		return nil, fmt.Errorf("expected TC_OBJECT at pos %d", d.pos)
	}
	d.pos++

	// Read class descriptor chain (most-derived → base)
	classDesc, err := d.readClassDesc()
	if err != nil {
		return nil, fmt.Errorf("reading object classdesc: %w", err)
	}

	// newHandle — the object being created
	handle := len(d.handles)
	result := make(map[string]interface{})
	d.handles = append(d.handles, result)

	// Read classdata for the entire class hierarchy
	if err := d.readClassData(classDesc, result); err != nil {
		return nil, fmt.Errorf("reading classdata: %w", err)
	}

	_ = handle
	return result, nil
}

// readClassDesc parses a class descriptor.
// Returns a chain from most-derived to base class (via .super).
// Handles TC_CLASSDESC, TC_NULL, TC_REFERENCE (to previously-read desc).
func (d *javaDeserializer) readClassDesc() (*classDescInfo, error) {
	if d.pos >= len(d.data) {
		return nil, fmt.Errorf("unexpected end reading classdesc")
	}

	tc := d.data[d.pos]
	switch tc {
	case _tcNull:
		d.pos++
		return nil, nil
	case _tcReference:
		d.pos++
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading classdesc ref handle")
		}
		h := int(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		if h < 0 || h >= len(d.handles) {
			return nil, fmt.Errorf("invalid classdesc handle: %d (have %d)", h, len(d.handles))
		}
		cd, ok := d.handles[h].(*classDescInfo)
		if !ok {
			return nil, fmt.Errorf("handle %d is not a classdesc", h)
		}
		return cd, nil
	case _tcClassDesc:
		// proceed below
	default:
		return nil, fmt.Errorf("expected classdesc tag, got 0x%02x at pos %d", tc, d.pos)
	}

	d.pos++ // consume TC_CLASSDESC

	// Class name (modified UTF-8)
	className, err := d.readUTF()
	if err != nil {
		return nil, fmt.Errorf("classdesc name: %w", err)
	}

	// serialVersionUID (8 bytes)
	if d.pos+8 > len(d.data) {
		return nil, fmt.Errorf("unexpected end reading serialVersionUID")
	}
	d.pos += 8

	// Assign handle for this classdesc
	handle := len(d.handles)
	info := &classDescInfo{
		className: className,
	}
	d.handles = append(d.handles, info)

	// classDescFlags (1 byte)
	if d.pos >= len(d.data) {
		return nil, fmt.Errorf("unexpected end reading classDescFlags")
	}
	info.flags = d.data[d.pos]
	d.pos++

	// Field count (2 bytes)
	if d.pos+2 > len(d.data) {
		return nil, fmt.Errorf("unexpected end reading field count")
	}
	fieldCount := int(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
	d.pos += 2

	// Read field descriptors
	info.fields = make([]javaFieldInfo, fieldCount)
	for i := 0; i < fieldCount; i++ {
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading field %d type code", i)
		}
		typeCode := d.data[d.pos]
		d.pos++

		fieldName, err := d.readUTF()
		if err != nil {
			return nil, fmt.Errorf("field %d name: %w", i, err)
		}

		f := javaFieldInfo{
			typeCode: typeCode,
			name:     fieldName,
		}

		// For array ('[') and object ('L') types, read className1
		if typeCode == '[' || typeCode == 'L' {
			cn, err := d.readObjectString()
			if err != nil {
				return nil, fmt.Errorf("field %d classname: %w", i, err)
			}
			f.className1 = cn
		}

		info.fields[i] = f
	}
	_ = handle

	// classAnnotation: only present if SC_SERIALIZABLE && SC_WRITE_METHOD
	if (info.flags&_scSerializable) != 0 && (info.flags&_scWriteMethod) != 0 {
		if err := d.skipObjectAnnotation(); err != nil {
			return nil, fmt.Errorf("class annotation: %w", err)
		}
	}

	// superClassDesc (recursive)
	super, err := d.readClassDesc()
	if err != nil {
		return nil, fmt.Errorf("super classdesc: %w", err)
	}
	info.super = super

	return info, nil
}

// readClassData reads field values for each class in the hierarchy and
// populates result. Walks the linked list from most-derived to base.
//
// For classes with SC_WRITE_METHOD (e.g. java.util.HashMap), the field
// data is encoded as TC_BLOCKDATA/TC_BLOCKDATALONG chunks terminated by
// TC_ENDBLOCKDATA. In that case we skip the inlined field reading and
// skip the block-data annotation instead.
func (d *javaDeserializer) readClassData(desc *classDescInfo, result map[string]interface{}) error {
	if desc == nil {
		return nil
	}

	hasWriteMethod := (desc.flags & _scWriteMethod) != 0

	// If this class has writeObject and the next byte looks like block data,
	// skip the inlined field reading — the actual data is in the annotation.
	if hasWriteMethod && d.pos < len(d.data) {
		tc := d.data[d.pos]
		if tc == _tcBlockData || tc == _tcBlockDataLong {
			if err := d.skipObjectAnnotation(); err != nil {
				return err
			}
			return d.readClassData(desc.super, result)
		}
	}

	// Read values for this class's fields (in declaration order)
	for _, f := range desc.fields {
		val, err := d.readFieldValue(f.typeCode)
		if err != nil {
			return fmt.Errorf("field %s: %w", f.name, err)
		}
		// Only set if not already set by a subclass shadow
		if _, exists := result[f.name]; !exists {
			result[f.name] = val
		}
	}

	// Object annotation if SC_WRITE_METHOD
	if hasWriteMethod {
		if err := d.skipObjectAnnotation(); err != nil {
			return err
		}
	}

	// Recurse into super class
	return d.readClassData(desc.super, result)
}

// readFieldValue reads a single field value based on its Java type code.
// Primitive values (B, C, D, F, I, J, S, Z) are inlined as raw bytes.
// Arrays ('[') and objects ('L') are content elements (tagged).
func (d *javaDeserializer) readFieldValue(typeCode byte) (interface{}, error) {
	switch typeCode {
	case 'B': // byte
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading byte")
		}
		v := int64(int8(d.data[d.pos]))
		d.pos++
		return v, nil
	case 'C': // char
		if d.pos+2 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading char")
		}
		v := binary.BigEndian.Uint16(d.data[d.pos : d.pos+2])
		d.pos += 2
		return v, nil
	case 'D': // double
		if d.pos+8 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading double")
		}
		bits := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		return math.Float64frombits(bits), nil
	case 'F': // float
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading float")
		}
		bits := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
		d.pos += 4
		return float64(math.Float32frombits(bits)), nil
	case 'I': // int
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading int")
		}
		v := int32(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		return int64(v), nil
	case 'J': // long
		if d.pos+8 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading long")
		}
		v := int64(binary.BigEndian.Uint64(d.data[d.pos : d.pos+8]))
		d.pos += 8
		return v, nil
	case 'S': // short
		if d.pos+2 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading short")
		}
		v := int16(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
		d.pos += 2
		return int64(v), nil
	case 'Z': // boolean
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading boolean")
		}
		v := d.data[d.pos] != 0
		d.pos++
		return v, nil
	case '[': // array — content element
		return d.readContent()
	case 'L': // object — content element
		return d.readContent()
	default:
		return nil, fmt.Errorf("unknown field type 0x%02x (%c)", typeCode, typeCode)
	}
}

// readString parses a TC_STRING (2-byte unsigned length + UTF-8 data).
func (d *javaDeserializer) readString() (string, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcString {
		return "", fmt.Errorf("expected TC_STRING at pos %d", d.pos)
	}
	d.pos++

	if d.pos+2 > len(d.data) {
		return "", fmt.Errorf("unexpected end reading string length")
	}
	length := int(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
	d.pos += 2

	if length < 0 || d.pos+length > len(d.data) {
		return "", fmt.Errorf("string length %d exceeds data at pos %d", length, d.pos)
	}
	s := string(d.data[d.pos : d.pos+length])
	d.pos += length

	d.handles = append(d.handles, s)
	return s, nil
}

// readLongString parses a TC_LONGSTRING (8-byte length + UTF-8 data).
func (d *javaDeserializer) readLongString() (string, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcLongString {
		return "", fmt.Errorf("expected TC_LONGSTRING at pos %d", d.pos)
	}
	d.pos++

	if d.pos+8 > len(d.data) {
		return "", fmt.Errorf("unexpected end reading long string length")
	}
	length := int(binary.BigEndian.Uint64(d.data[d.pos : d.pos+8]))
	d.pos += 8

	if length < 0 || d.pos+length > len(d.data) {
		return "", fmt.Errorf("long string length %d exceeds data", length)
	}
	s := string(d.data[d.pos : d.pos+length])
	d.pos += length

	d.handles = append(d.handles, s)
	return s, nil
}

// readObjectString reads a string value that is a content element
// (TC_STRING, TC_LONGSTRING, or TC_REFERENCE to a previously-read string).
func (d *javaDeserializer) readObjectString() (string, error) {
	if d.pos >= len(d.data) {
		return "", fmt.Errorf("unexpected end reading object string")
	}

	tc := d.data[d.pos]
	switch tc {
	case _tcString:
		return d.readString()
	case _tcLongString:
		return d.readLongString()
	case _tcReference:
		d.pos++
		if d.pos+4 > len(d.data) {
			return "", fmt.Errorf("unexpected end reading string ref handle")
		}
		h := int(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		if h < 0 || h >= len(d.handles) {
			return "", fmt.Errorf("invalid string handle: %d (have %d)", h, len(d.handles))
		}
		s, ok := d.handles[h].(string)
		if !ok {
			return "", fmt.Errorf("handle %d is not a string", h)
		}
		return s, nil
	default:
		return "", fmt.Errorf("expected string tag, got 0x%02x at pos %d", tc, d.pos)
	}
}

// readArray parses a TC_ARRAY element.
//
// For primitive arrays (e.g. int[]), elements are packed inline without tags.
// For object arrays, each element is a full content element.
func (d *javaDeserializer) readArray() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcArray {
		return nil, fmt.Errorf("expected TC_ARRAY at pos %d", d.pos)
	}
	d.pos++

	classDesc, err := d.readClassDesc()
	if err != nil {
		return nil, fmt.Errorf("array classdesc: %w", err)
	}
	if classDesc == nil {
		return nil, fmt.Errorf("null array classdesc")
	}

	// Array size (4 bytes)
	if d.pos+4 > len(d.data) {
		return nil, fmt.Errorf("unexpected end reading array size")
	}
	size := int(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
	d.pos += 4

	// Assign handle
	handle := len(d.handles)
	d.handles = append(d.handles, nil) // placeholder

	// Determine element type from class name (e.g. "[B", "[I", "[Ljava/lang/String;")
	elemType := byte('L')
	if len(classDesc.className) >= 2 && classDesc.className[0] == '[' {
		elemType = classDesc.className[1]
	}

	result := make([]interface{}, size)
	for i := 0; i < size; i++ {
		var val interface{}
		var err error
		if isPrimitiveTypeCode(elemType) {
			// Primitive arrays: raw values, no tags
			val, err = d.readRawPrimitive(elemType)
		} else {
			// Object arrays: full content elements
			val, err = d.readContent()
		}
		if err != nil {
			return nil, fmt.Errorf("array[%d]: %w", i, err)
		}
		result[i] = val
	}

	d.handles[handle] = result
	return result, nil
}

// readEnum parses a TC_ENUM element. Returns the enum constant name.
func (d *javaDeserializer) readEnum() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcEnum {
		return nil, fmt.Errorf("expected TC_ENUM at pos %d", d.pos)
	}
	d.pos++

	_, err := d.readClassDesc()
	if err != nil {
		return nil, fmt.Errorf("enum classdesc: %w", err)
	}

	enumName, err := d.readObjectString()
	if err != nil {
		return nil, fmt.Errorf("enum name: %w", err)
	}

	handle := len(d.handles)
	d.handles = append(d.handles, enumName)
	_ = handle

	return enumName, nil
}

// readClass parses a TC_CLASS element (a Class literal reference).
func (d *javaDeserializer) readClass() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcClass {
		return nil, fmt.Errorf("expected TC_CLASS at pos %d", d.pos)
	}
	d.pos++

	desc, err := d.readClassDesc()
	if err != nil {
		return nil, fmt.Errorf("class literal: %w", err)
	}

	handle := len(d.handles)
	className := ""
	if desc != nil {
		className = desc.className
	}
	d.handles = append(d.handles, className)
	_ = handle

	return map[string]interface{}{"class": className}, nil
}

// readReference parses a TC_REFERENCE and returns the previously-seen value.
func (d *javaDeserializer) readReference() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcReference {
		return nil, fmt.Errorf("expected TC_REFERENCE at pos %d", d.pos)
	}
	d.pos++

	if d.pos+4 > len(d.data) {
		return nil, fmt.Errorf("unexpected end reading ref handle")
	}
	h := int(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
	d.pos += 4

	if h < 0 || h >= len(d.handles) {
		return nil, fmt.Errorf("invalid handle: %d (have %d)", h, len(d.handles))
	}
	return d.handles[h], nil
}

// readUTF reads a Java-modified UTF-8 string (2-byte unsigned length + bytes).
// For class/field names standard UTF-8 decoding is sufficient.
func (d *javaDeserializer) readUTF() (string, error) {
	if d.pos+2 > len(d.data) {
		return "", fmt.Errorf("unexpected end reading UTF length")
	}
	length := int(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
	d.pos += 2

	if length == 0 {
		return "", nil
	}
	if d.pos+length > len(d.data) {
		return "", fmt.Errorf("UTF length %d exceeds data", length)
	}
	s := string(d.data[d.pos : d.pos+length])
	d.pos += length
	return s, nil
}

// readRawPrimitive reads a single primitive value without a preceding tag.
// Used when reading elements of a primitive array.
func (d *javaDeserializer) readRawPrimitive(typeCode byte) (interface{}, error) {
	switch typeCode {
	case 'B':
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw byte")
		}
		v := int64(int8(d.data[d.pos]))
		d.pos++
		return v, nil
	case 'C':
		if d.pos+2 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw char")
		}
		v := binary.BigEndian.Uint16(d.data[d.pos : d.pos+2])
		d.pos += 2
		return v, nil
	case 'D':
		if d.pos+8 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw double")
		}
		bits := binary.BigEndian.Uint64(d.data[d.pos : d.pos+8])
		d.pos += 8
		return math.Float64frombits(bits), nil
	case 'F':
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw float")
		}
		bits := binary.BigEndian.Uint32(d.data[d.pos : d.pos+4])
		d.pos += 4
		return float64(math.Float32frombits(bits)), nil
	case 'I':
		if d.pos+4 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw int")
		}
		v := int32(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
		d.pos += 4
		return int64(v), nil
	case 'J':
		if d.pos+8 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw long")
		}
		v := int64(binary.BigEndian.Uint64(d.data[d.pos : d.pos+8]))
		d.pos += 8
		return v, nil
	case 'S':
		if d.pos+2 > len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw short")
		}
		v := int16(binary.BigEndian.Uint16(d.data[d.pos : d.pos+2]))
		d.pos += 2
		return int64(v), nil
	case 'Z':
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading raw boolean")
		}
		v := d.data[d.pos] != 0
		d.pos++
		return v, nil
	default:
		return nil, fmt.Errorf("not a primitive type: 0x%02x", typeCode)
	}
}

// isPrimitiveTypeCode returns true for Java primitive type codes.
func isPrimitiveTypeCode(c byte) bool {
	switch c {
	case 'B', 'C', 'D', 'F', 'I', 'J', 'S', 'Z':
		return true
	}
	return false
}

// skipObjectAnnotation reads and discards the object annotation block
// (one or more TC_BLOCKDATA/TC_BLOCKDATALONG chunks, terminated by TC_ENDBLOCKDATA).
func (d *javaDeserializer) skipObjectAnnotation() error {
	for d.pos < len(d.data) {
		tc := d.data[d.pos]
		switch tc {
		case _tcEndBlockData:
			d.pos++
			return nil
		case _tcBlockData:
			if _, err := d.skipBlockData(); err != nil {
				return err
			}
		case _tcBlockDataLong:
			if _, err := d.skipBlockDataLong(); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unexpected tag 0x%02x in annotation at pos %d", tc, d.pos)
		}
	}
	return fmt.Errorf("unexpected end of data in annotation")
}

// skipBlockData skips a TC_BLOCKDATA or TC_BLOCKDATALONG chunk.
// Also handles TC_ENDBLOCKDATA.
func (d *javaDeserializer) skipBlockData() (interface{}, error) {
	if d.pos >= len(d.data) {
		return nil, fmt.Errorf("unexpected end at blockdata")
	}
	tc := d.data[d.pos]
	switch tc {
	case _tcBlockData:
		d.pos++
		if d.pos >= len(d.data) {
			return nil, fmt.Errorf("unexpected end reading blockdata size")
		}
		size := int(d.data[d.pos])
		d.pos++
		if d.pos+size > len(d.data) {
			return nil, fmt.Errorf("blockdata size %d exceeds data", size)
		}
		d.pos += size
		return nil, nil
	case _tcBlockDataLong:
		return d.skipBlockDataLong()
	case _tcEndBlockData:
		d.pos++
		return nil, nil
	default:
		return nil, fmt.Errorf("expected blockdata, got 0x%02x at pos %d", tc, d.pos)
	}
}

// ParseJavaSerializedArgs extracts Java serialization arguments from a
// compactedjava Dubbo body starting at the given byte offset.
//
// body is the full Dubbo body; startPos marks where the Java serialization
// stream begins (after the compactedjava header strings). Returns a map of
// field-name to value, or nil with error if nothing could be parsed.
func ParseJavaSerializedArgs(body []byte, startPos int) (map[string]interface{}, error) {
	if startPos < 0 || startPos >= len(body) {
		return nil, fmt.Errorf("invalid start position %d for body of length %d", startPos, len(body))
	}
	return deserializeJavaArgs(body[startPos:])
}

// skipClassDescWithData reads and skips a TC_OBJECT's class descriptor
// chain and its associated classdata, positioning the deserializer just
// past the last classdata block. Used to skip past a HashMap object so
// its entries can be read as inline content elements.
func (d *javaDeserializer) skipClassDescWithData() error {
	desc, err := d.readClassDesc()
	if err != nil {
		return fmt.Errorf("classdesc: %w", err)
	}
	return d.skipClassData(desc)
}

// skipClassData skips classdata for a class hierarchy without populating
// a result map. For SC_WRITE_METHOD classes (e.g. HashMap), the data
// is in block-data annotation form and is skipped via skipObjectAnnotation.
func (d *javaDeserializer) skipClassData(desc *classDescInfo) error {
	if desc == nil {
		return nil
	}

	hasWriteMethod := (desc.flags & _scWriteMethod) != 0

	if hasWriteMethod && d.pos < len(d.data) {
		tc := d.data[d.pos]
		if tc == _tcBlockData || tc == _tcBlockDataLong {
			if err := d.skipObjectAnnotation(); err != nil {
				return err
			}
			return d.skipClassData(desc.super)
		}
	}

	// Skip primitive field values individually
	for _, f := range desc.fields {
		if isPrimitiveTypeCode(f.typeCode) {
			if _, err := d.readFieldValue(f.typeCode); err != nil {
				return err
			}
		} else {
			if _, err := d.readContent(); err != nil {
				return err
			}
		}
	}

	if hasWriteMethod {
		if err := d.skipObjectAnnotation(); err != nil {
			return err
		}
	}

	return d.skipClassData(desc.super)
}

// findClassDesc scans data[startPos:] for a TC_CLASSDESC whose class name
// equals className. Returns the byte offset of TC_CLASSDESC, or -1 if not found.
func findClassDesc(data []byte, startPos int, className string) int {
	nameLen := len(className)
	for pos := startPos; pos+3+nameLen <= len(data); pos++ {
		if data[pos] != _tcClassDesc {
			continue
		}
		utfLen := int(binary.BigEndian.Uint16(data[pos+1 : pos+3]))
		if utfLen != nameLen {
			continue
		}
		if pos+3+nameLen > len(data) {
			continue
		}
		if string(data[pos+3:pos+3+nameLen]) == className {
			return pos
		}
	}
	return -1
}

// ParseJavaSerializedAttachments parses a java.util.HashMap from a
// compactedjava Dubbo body and returns its string key-value entries.
//
// body is the full Dubbo body; startPos marks where to begin scanning
// for the HashMap (typically m.ArgStartPos). Returns a map of attachment
// key to value, or nil with error if no HashMap entries could be parsed.
func ParseJavaSerializedAttachments(body []byte, startPos int) (map[string]string, error) {
	pos := findClassDesc(body, startPos, "java.util.HashMap")
	if pos < 0 {
		return nil, fmt.Errorf("java.util.HashMap classdesc not found")
	}
	// Expect TC_OBJECT exactly before the classdesc
	if pos < 1 || body[pos-1] != _tcObject {
		return nil, fmt.Errorf("expected TC_OBJECT before HashMap classdesc at %d", pos)
	}

	d := &javaDeserializer{data: body, pos: pos - 1}

	// Consume TC_OBJECT tag
	d.pos++

	// Skip the classdesc chain and classdata to reach the entries
	if err := d.skipClassDescWithData(); err != nil {
		return nil, fmt.Errorf("skipping HashMap: %w", err)
	}

	// Read entries as key-value string pairs
	result := make(map[string]string)
	for d.pos < len(d.data) {
		// Read key — expect a string
		key, err := d.readObjectString()
		if err != nil {
			break
		}
		if d.pos >= len(d.data) {
			break
		}
		// Read value — may be string, number, boolean, null, etc.
		val, err := d.readEntryValue()
		if err != nil {
			result[key] = "<parse-error>"
			break
		}
		result[key] = val
	}

	if len(result) == 0 {
		return nil, fmt.Errorf("no HashMap entries parsed")
	}
	return result, nil
}

// readEntryValue reads an attachment value, converting common Java
// serialization types to a string representation.
func (d *javaDeserializer) readEntryValue() (string, error) {
	if d.pos >= len(d.data) {
		return "", fmt.Errorf("eof reading entry value")
	}
	tc := d.data[d.pos]
	switch tc {
	case _tcString:
		return d.readString()
	case _tcLongString:
		return d.readLongString()
	case _tcReference:
		ref, err := d.readReference()
		if err != nil {
			return "", err
		}
		if s, ok := ref.(string); ok {
			return s, nil
		}
		return fmt.Sprintf("%v", ref), nil
	case _tcNull:
		d.pos++
		return "", nil
	case _tcObject:
		// Boxed primitives (Integer, Long, Boolean, etc.) or nested objects.
		obj, err := d.readObject()
		if err != nil {
			return "", err
		}
		// Try the "value" field first (boxed primitives)
		if m, ok := obj.(map[string]interface{}); ok {
			if v, ok2 := m["value"]; ok2 {
				return fmt.Sprintf("%v", v), nil
			}
		}
		return fmt.Sprintf("%v", obj), nil
	default:
		// Unknown type — skip one content element to avoid getting stuck
		_, err := d.readContent()
		if err != nil {
			return "", err
		}
		return "<non-string>", nil
	}
}

// skipBlockDataLong skips a TC_BLOCKDATALONG chunk.
func (d *javaDeserializer) skipBlockDataLong() (interface{}, error) {
	if d.pos >= len(d.data) || d.data[d.pos] != _tcBlockDataLong {
		return nil, fmt.Errorf("expected TC_BLOCKDATALONG at pos %d", d.pos)
	}
	d.pos++
	if d.pos+4 > len(d.data) {
		return nil, fmt.Errorf("unexpected end reading blockdata long size")
	}
	size := int(binary.BigEndian.Uint32(d.data[d.pos : d.pos+4]))
	d.pos += 4
	if size < 0 || d.pos+size > len(d.data) {
		return nil, fmt.Errorf("blockdata long size %d exceeds data", size)
	}
	d.pos += size
	return nil, nil
}
