package trustlist

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

func buildTrustListJWT(t *testing.T, payload map[string]any) string {
	t.Helper()
	header := map[string]any{"alg": "none"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(payloadJSON) + "."
}

func TestParse_BasicTrustList(t *testing.T) {
	payload := map[string]any{
		"ListAndSchemeInformation": map[string]any{
			"LoTEType": "http://uri.etsi.org/19602/LoTEType/local",
			"SchemeOperatorName": []any{
				map[string]any{"lang": "en", "value": "Test Operator"},
			},
			"ListIssueDatetime": "2025-01-01T00:00:00Z",
		},
		"TrustedEntitiesList": []any{
			map[string]any{
				"TrustedEntityInformation": map[string]any{
					"TEName": []any{
						map[string]any{"lang": "en", "value": "Test Entity"},
					},
				},
				"TrustedEntityServices": []any{
					map[string]any{
						"ServiceInformation": map[string]any{
							"ServiceTypeIdentifier": "http://uri.etsi.org/19602/SvcType/Issuance",
							"ServiceDigitalIdentity": map[string]any{
								"X509Certificates": []any{},
							},
						},
					},
				},
			},
		},
	}

	raw := buildTrustListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}

	if tl.SchemeInfo == nil {
		t.Fatal("expected SchemeInfo")
	}
	if tl.SchemeInfo.LoTEType != "http://uri.etsi.org/19602/LoTEType/local" {
		t.Errorf("LoTEType = %q", tl.SchemeInfo.LoTEType)
	}
	if tl.SchemeInfo.SchemeOperatorName != "Test Operator" {
		t.Errorf("SchemeOperatorName = %q", tl.SchemeInfo.SchemeOperatorName)
	}

	if len(tl.Entities) != 1 {
		t.Fatalf("expected 1 entity, got %d", len(tl.Entities))
	}
	if tl.Entities[0].Name != "Test Entity" {
		t.Errorf("entity name = %q", tl.Entities[0].Name)
	}
	if len(tl.Entities[0].Services) != 1 {
		t.Fatalf("expected 1 service, got %d", len(tl.Entities[0].Services))
	}
	if tl.Entities[0].Services[0].ServiceType != "http://uri.etsi.org/19602/SvcType/Issuance" {
		t.Errorf("service type = %q", tl.Entities[0].Services[0].ServiceType)
	}
}

func TestParse_InvalidJWT(t *testing.T) {
	_, err := Parse("not.a")
	if err == nil {
		t.Error("expected error for invalid JWT")
	}
}

func TestParse_EmptyEntities(t *testing.T) {
	payload := map[string]any{
		"TrustedEntitiesList": []any{},
	}
	raw := buildTrustListJWT(t, payload)
	tl, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse() error: %v", err)
	}
	if len(tl.Entities) != 0 {
		t.Errorf("expected 0 entities, got %d", len(tl.Entities))
	}
}

func TestExtractPublicKeys_Empty(t *testing.T) {
	tl := &TrustList{}
	keys := ExtractPublicKeys(tl)
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}
