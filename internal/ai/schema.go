package ai

import (
	"bytes"
	"encoding/json"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"strconv"
	"unicode/utf8"
)

func validateOutput(output, schema []byte, input validatedInput) error {
	if len(output) == 0 || !utf8.Valid(output) || validateJSONDocument(output, true) != nil {
		return &Failure{Reason: FailureSchemaInvalid}
	}
	var value any
	valueDecoder := json.NewDecoder(bytes.NewReader(output))
	valueDecoder.UseNumber()
	if err := valueDecoder.Decode(&value); err != nil {
		return &Failure{Reason: FailureSchemaInvalid}
	}
	var schemaValue map[string]any
	schemaDecoder := json.NewDecoder(bytes.NewReader(schema))
	schemaDecoder.UseNumber()
	if err := schemaDecoder.Decode(&schemaValue); err != nil || !matchesSchema(value, schemaValue) {
		return &Failure{Reason: FailureSchemaInvalid}
	}

	var binding struct {
		EvidenceIDs []string `json:"evidence_ids"`
		Policy      struct {
			TargetIP    string   `json:"target_ip"`
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"policy"`
		Candidate struct {
			TargetIP    string   `json:"target_ip"`
			EvidenceIDs []string `json:"evidence_ids"`
		} `json:"nftables_command_candidate"`
	}
	if err := json.Unmarshal(output, &binding); err != nil ||
		!validEvidenceSelection(binding.EvidenceIDs, input.evidenceIDs) ||
		!equalStrings(binding.EvidenceIDs, binding.Policy.EvidenceIDs) ||
		!equalStrings(binding.EvidenceIDs, binding.Candidate.EvidenceIDs) ||
		binding.Policy.TargetIP != input.targetIP || binding.Candidate.TargetIP != input.targetIP {
		return &Failure{Reason: FailureEvidenceInvalid}
	}
	return nil
}

func validEvidenceSelection(ids []string, allowed map[string]struct{}) bool {
	if len(ids) == 0 || len(ids) > MaxEvidenceRefs {
		return false
	}
	previous := ""
	for index, id := range ids {
		if index > 0 && id <= previous {
			return false
		}
		if _, ok := allowed[id]; !ok {
			return false
		}
		previous = id
	}
	return true
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func matchesSchema(value any, schema map[string]any) bool {
	if constant, exists := schema["const"]; exists && !reflect.DeepEqual(value, constant) {
		return false
	}
	if enum, exists := schema["enum"].([]any); exists {
		matched := false
		for _, candidate := range enum {
			if reflect.DeepEqual(value, candidate) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	typeName, _ := schema["type"].(string)
	switch typeName {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		properties, _ := schema["properties"].(map[string]any)
		if additional, exists := schema["additionalProperties"].(bool); exists && !additional {
			for key := range object {
				if _, known := properties[key]; !known {
					return false
				}
			}
		}
		if required, ok := schema["required"].([]any); ok {
			for _, item := range required {
				name, ok := item.(string)
				if !ok {
					return false
				}
				if _, exists := object[name]; !exists {
					return false
				}
			}
		}
		for name, childValue := range object {
			childSchema, exists := properties[name].(map[string]any)
			if !exists || !matchesSchema(childValue, childSchema) {
				return false
			}
		}
	case "array":
		array, ok := value.([]any)
		if !ok || !withinIntegerBound(len(array), schema, "minItems", "maxItems") {
			return false
		}
		if itemSchema, ok := schema["items"].(map[string]any); ok {
			for _, item := range array {
				if !matchesSchema(item, itemSchema) {
					return false
				}
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok || !withinIntegerBound(utf8.RuneCountInString(text), schema, "minLength", "maxLength") {
			return false
		}
		if pattern, ok := schema["pattern"].(string); ok {
			compiled, err := regexp.Compile(pattern)
			if err != nil || !compiled.MatchString(text) {
				return false
			}
		}
		if format, _ := schema["format"].(string); format == "ipv4" {
			address, err := netip.ParseAddr(text)
			if err != nil || !address.Is4() || address.String() != text {
				return false
			}
		}
	case "integer":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		integer, err := strconv.ParseInt(number.String(), 10, 64)
		if err != nil || !withinNumberBound(float64(integer), schema) {
			return false
		}
	case "number":
		number, ok := value.(json.Number)
		if !ok {
			return false
		}
		decimal, err := strconv.ParseFloat(number.String(), 64)
		if err != nil || math.IsNaN(decimal) || math.IsInf(decimal, 0) || !withinNumberBound(decimal, schema) {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	case "":
		// const/enum-only schemas are valid.
	default:
		return false
	}
	return true
}

func withinIntegerBound(value int, schema map[string]any, minimum, maximum string) bool {
	if raw, exists := schema[minimum].(json.Number); exists {
		bound, err := strconv.Atoi(raw.String())
		if err != nil || value < bound {
			return false
		}
	}
	if raw, exists := schema[maximum].(json.Number); exists {
		bound, err := strconv.Atoi(raw.String())
		if err != nil || value > bound {
			return false
		}
	}
	return true
}

func withinNumberBound(value float64, schema map[string]any) bool {
	if raw, exists := schema["minimum"].(json.Number); exists {
		bound, err := strconv.ParseFloat(raw.String(), 64)
		if err != nil || value < bound {
			return false
		}
	}
	if raw, exists := schema["maximum"].(json.Number); exists {
		bound, err := strconv.ParseFloat(raw.String(), 64)
		if err != nil || value > bound {
			return false
		}
	}
	return true
}
