package ai

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"unicode/utf8"
)

const (
	maxArtifactBytes = 1 << 20

	// These digests pin the byte-exact, checked-in v0.1 analysis contract.
	// LoadArtifacts is the production file-loading boundary and refuses drift;
	// ParseArtifacts remains available for isolated transport/schema tests.
	PinnedInputSchemaDigest  = "sha256:43c89767ba0187facecee2d3468add7d01eda0153d8c185d24479d0bfd218642"
	PinnedSystemPromptDigest = "sha256:82cf667146ba37ef63850b873a269f3b8bbfd4aeff3103524add5718cf79eba4"
	PinnedOutputSchemaDigest = "sha256:6e20c50b99147732098609a0821d9ed30f10966922f8392326f032286f9573b9"
)

type ArtifactPaths struct {
	InputSchema  string
	SystemPrompt string
	OutputSchema string
}

type Artifacts struct {
	inputSchema        []byte
	systemPrompt       []byte
	outputSchema       []byte
	inputSchemaDigest  string
	promptDigest       string
	outputSchemaDigest string
}

func LoadArtifacts(paths ArtifactPaths) (Artifacts, error) {
	input, err := readArtifact(paths.InputSchema)
	if err != nil {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	prompt, err := readArtifact(paths.SystemPrompt)
	if err != nil {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	output, err := readArtifact(paths.OutputSchema)
	if err != nil {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	artifacts, err := ParseArtifacts(input, prompt, output)
	if err != nil || artifacts.inputSchemaDigest != PinnedInputSchemaDigest ||
		artifacts.promptDigest != PinnedSystemPromptDigest ||
		artifacts.outputSchemaDigest != PinnedOutputSchemaDigest {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	return artifacts, nil
}

// InputSchemaDigest returns the immutable digest without exposing schema
// bytes. It is safe to bind into audit and validation configuration.
func (a Artifacts) InputSchemaDigest() string { return a.inputSchemaDigest }

// PromptDigest returns the immutable system-prompt digest without exposing
// prompt bytes.
func (a Artifacts) PromptDigest() string { return a.promptDigest }

// OutputSchemaDigest returns the immutable Structured Outputs schema digest.
func (a Artifacts) OutputSchemaDigest() string { return a.outputSchemaDigest }

func readArtifact(path string) ([]byte, error) {
	if path == "" {
		return nil, io.ErrUnexpectedEOF
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxArtifactBytes+1))
	if err != nil || len(data) > maxArtifactBytes {
		return nil, io.ErrUnexpectedEOF
	}
	return data, nil
}

func ParseArtifacts(inputSchema, systemPrompt, outputSchema []byte) (Artifacts, error) {
	if len(inputSchema) == 0 || len(systemPrompt) == 0 || len(outputSchema) == 0 ||
		len(inputSchema) > maxArtifactBytes || len(systemPrompt) > maxArtifactBytes || len(outputSchema) > maxArtifactBytes ||
		!utf8.Valid(inputSchema) || !utf8.Valid(systemPrompt) || !utf8.Valid(outputSchema) || bytes.IndexByte(systemPrompt, 0) >= 0 {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	if err := validateJSONDocument(inputSchema, true); err != nil {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}
	if err := validateJSONDocument(outputSchema, true); err != nil {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}

	var output map[string]any
	decoder := json.NewDecoder(bytes.NewReader(outputSchema))
	decoder.UseNumber()
	if err := decoder.Decode(&output); err != nil || output["type"] != "object" {
		return Artifacts{}, &Failure{Reason: FailureConfiguration}
	}

	return Artifacts{
		inputSchema:        bytes.Clone(inputSchema),
		systemPrompt:       bytes.Clone(systemPrompt),
		outputSchema:       bytes.Clone(outputSchema),
		inputSchemaDigest:  digest(inputSchema),
		promptDigest:       digest(systemPrompt),
		outputSchemaDigest: digest(outputSchema),
	}, nil
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return "sha256:" + hex.EncodeToString(sum[:])
}
