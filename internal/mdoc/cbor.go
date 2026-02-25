package mdoc

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

var cborDecMode cbor.DecMode

func init() {
	var err error
	cborDecMode, err = cbor.DecOptions{
		IntDec: cbor.IntDecConvertSigned,
	}.DecMode()
	if err != nil {
		panic(err)
	}
}

// unmarshalTag24 decodes CBOR Tag 24, returning the inner bytes.
func unmarshalTag24(data []byte) ([]byte, error) {
	var raw cbor.RawTag
	if err := cborDecMode.Unmarshal(data, &raw); err != nil {
		// Maybe it's not tagged, try raw
		return data, nil
	}
	if raw.Number != 24 {
		return data, nil
	}

	var inner []byte
	if err := cborDecMode.Unmarshal(raw.Content, &inner); err != nil {
		return nil, fmt.Errorf("unwrapping tag 24 content: %w", err)
	}
	return inner, nil
}

// decodeCBOR decodes CBOR bytes into a generic Go value.
func decodeCBOR(data []byte) (any, error) {
	var result any
	if err := cborDecMode.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return result, nil
}

// convertCBORMapToStringKeys converts map[any]any to map[string]any recursively.
func convertCBORMapToStringKeys(m map[any]any) map[string]any {
	result := make(map[string]any)
	for k, v := range m {
		key := fmt.Sprintf("%v", k)
		result[key] = convertCBORValue(v)
	}
	return result
}
