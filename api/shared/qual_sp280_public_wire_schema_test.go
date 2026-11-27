package shared

import (
	"encoding/json"
	"math"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// wireSchemaFixture implements only the JSON Schema keywords used by this
// artifact. It is a local test oracle, not a runtime JSON Schema validator.
type wireSchemaFixture struct {
	Dialect     string                        `json:"$schema"`
	Title       string                        `json:"title"`
	Description string                        `json:"description"`
	Defs        map[string]*wireSchemaFixture `json:"$defs"`
	Ref         string                        `json:"$ref"`
	Type        string                        `json:"type"`
	Properties  map[string]*wireSchemaFixture `json:"properties"`
	Required    []string                      `json:"required"`
	Additional  *bool                         `json:"additionalProperties"`
	Items       *wireSchemaFixture            `json:"items"`
	AnyOf       []*wireSchemaFixture          `json:"anyOf"`
	Enum        []any                         `json:"enum"`
	Const       any                           `json:"const"`
	Pattern     string                        `json:"pattern"`
	MinLength   *int                          `json:"minLength"`
	Minimum     *float64                      `json:"minimum"`
	Maximum     *float64                      `json:"maximum"`
	Not         *wireSchemaFixture            `json:"not"`
	If          *wireSchemaFixture            `json:"if"`
	Then        *wireSchemaFixture            `json:"then"`
	Else        *wireSchemaFixture            `json:"else"`
}

func (s *wireSchemaFixture) verify(t *testing.T, defs map[string]*wireSchemaFixture) {
	t.Helper()
	if s.Ref != "" {
		require.True(t, strings.HasPrefix(s.Ref, "#/$defs/"))
		require.Contains(t, defs, strings.TrimPrefix(s.Ref, "#/$defs/"))
	}
	if s.Pattern != "" {
		_, err := regexp.Compile(s.Pattern)
		require.NoError(t, err)
	}
	for _, key := range s.Required {
		require.Contains(t, s.Properties, key)
	}
	for _, child := range s.Properties {
		child.verify(t, defs)
	}
	for _, child := range s.AnyOf {
		child.verify(t, defs)
	}
	for _, child := range []*wireSchemaFixture{s.Items, s.Not, s.If, s.Then, s.Else} {
		if child != nil {
			child.verify(t, defs)
		}
	}
}

func (s *wireSchemaFixture) matches(value any, defs map[string]*wireSchemaFixture) bool {
	if s.Ref != "" && !defs[strings.TrimPrefix(s.Ref, "#/$defs/")].matches(value, defs) {
		return false
	}
	switch s.Type {
	case "null":
		if value != nil {
			return false
		}
	case "string":
		if _, ok := value.(string); !ok {
			return false
		}
	case "integer":
		number, ok := value.(float64)
		if !ok || math.Trunc(number) != number {
			return false
		}
	case "object":
		if _, ok := value.(map[string]any); !ok {
			return false
		}
	case "array":
		if _, ok := value.([]any); !ok {
			return false
		}
	case "":
	default:
		return false
	}
	if s.Const != nil && !reflect.DeepEqual(s.Const, value) {
		return false
	}
	if len(s.Enum) != 0 {
		found := false
		for _, option := range s.Enum {
			found = found || reflect.DeepEqual(option, value)
		}
		if !found {
			return false
		}
	}
	if len(s.AnyOf) != 0 {
		found := false
		for _, option := range s.AnyOf {
			found = found || option.matches(value, defs)
		}
		if !found {
			return false
		}
	}
	if text, ok := value.(string); ok {
		if s.Pattern != "" && !regexp.MustCompile(s.Pattern).MatchString(text) {
			return false
		}
		if s.MinLength != nil && len([]rune(text)) < *s.MinLength {
			return false
		}
	}
	if number, ok := value.(float64); ok {
		if s.Minimum != nil && number < *s.Minimum || s.Maximum != nil && number > *s.Maximum {
			return false
		}
	}
	if object, ok := value.(map[string]any); ok {
		for _, key := range s.Required {
			if _, exists := object[key]; !exists {
				return false
			}
		}
		for key, v := range object {
			child, known := s.Properties[key]
			if known && !child.matches(v, defs) || !known && s.Additional != nil && !*s.Additional {
				return false
			}
		}
	}
	if items, ok := value.([]any); ok && s.Items != nil {
		for _, item := range items {
			if !s.Items.matches(item, defs) {
				return false
			}
		}
	}
	if s.Not != nil && s.Not.matches(value, defs) {
		return false
	}
	if s.If != nil {
		if s.If.matches(value, defs) {
			return s.Then == nil || s.Then.matches(value, defs)
		}
		return s.Else == nil || s.Else.matches(value, defs)
	}
	return true
}

func TestQualSP280PublicObservationWireSchema(t *testing.T) {
	schemaBytes, err := os.ReadFile("observation-v1.schema.json")
	require.NoError(t, err)
	var schema wireSchemaFixture
	decoder := json.NewDecoder(strings.NewReader(string(schemaBytes)))
	decoder.DisallowUnknownFields()
	require.NoError(t, decoder.Decode(&schema))
	require.Equal(t, "https://json-schema.org/draft/2020-12/schema", schema.Dialect)
	require.Equal(t, "#/$defs/ObservationReportV1", schema.Ref)
	schema.verify(t, schema.Defs)
	for _, definition := range schema.Defs {
		definition.verify(t, schema.Defs)
	}

	// No new field roster is derived from the DTO. Cross-check the new schema
	// artifact against the actual JSON tags; the independent R86 Go roster is
	// covered by the existing schema contract test.
	dtos := map[string]any{
		"ObservationReportV1": ObservationReportV1{}, "PublicSubject": PublicObservationSubject{},
		"PublicObservation": PublicObservation{}, "PublicProvenance": PublicObservationProvenance{},
		"PublicFinalityBasis": PublicObservationFinalityBasis{}, "PublicValue": PublicObservationValue{},
		"PublicGasRefund": PublicObservationGasRefund{},
	}
	count := 0
	for name, dto := range dtos {
		definition := schema.Defs[name]
		require.NotNil(t, definition)
		typ := reflect.TypeOf(dto)
		require.Len(t, definition.Properties, typ.NumField())
		require.Len(t, definition.Required, typ.NumField())
		require.NotNil(t, definition.Additional)
		require.True(t, *definition.Additional)
		for i := 0; i < typ.NumField(); i++ {
			field := typ.Field(i)
			key := field.Tag.Get("json")
			require.Contains(t, definition.Required, key)
			shape := definition.Properties[key]
			require.NotNil(t, shape)
			nullable := shape.matches(nil, schema.Defs)
			require.Equal(t, field.Type.Kind() == reflect.Pointer || field.Type.Kind() == reflect.Slice, nullable, key)
			count++
		}
	}
	require.Equal(t, 63, count)

	maxNonce := ^uint64(0)
	subject, err := ObservationSubjectFromPublicTokenFields("DEMO-abcdef", &maxNonce)
	require.NoError(t, err)
	for _, report := range []ObservationReportV1{
		{SchemaVersion: ObservationVersionV1, Availability: ObservationUnknown, Subject: subject},
		{SchemaVersion: ObservationVersionV1, Availability: ObservationUnknown},
		{SchemaVersion: ObservationVersionV1, Availability: ObservationAvailable, Observations: []PublicObservation{}},
	} {
		wire, err := EncodeObservationReport(report)
		require.NoError(t, err)
		var sample map[string]any
		require.NoError(t, json.Unmarshal(wire, &sample))
		require.True(t, schema.matches(sample, schema.Defs))
		sample["futureCaption"] = "sample display"
		require.True(t, schema.matches(sample, schema.Defs))
		sample["schemaVersion"] = "future-display"
		require.False(t, schema.matches(sample, schema.Defs))
	}

	// Primitive representation assertions, not native or authority semantics.
	for _, text := range []string{"0", "18446744073709551615"} {
		require.True(t, schema.Defs["UInt64Dec"].matches(text, schema.Defs))
	}
	for _, text := range []string{"01", "18446744073709551616", "0\n"} {
		require.False(t, schema.Defs["UInt64Dec"].matches(text, schema.Defs))
	}
	require.True(t, schema.Defs["UInt"].matches("18446744073709551616000", schema.Defs))
	require.True(t, schema.Defs["UInt32"].matches(float64(4294967295), schema.Defs))
	require.False(t, schema.Defs["UInt32"].matches(float64(4294967296), schema.Defs))
}
