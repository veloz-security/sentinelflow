package dispatchruntime

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/devwooops/sentinelflow/internal/enforcement/capability"
)

type IssuedCapability struct {
	Signed   capability.SignedCapability
	Verified capability.VerifiedCapability
}

func (IssuedCapability) String() string {
	return "dispatchruntime.IssuedCapability{capability:[REDACTED]}"
}
func (i IssuedCapability) GoString() string { return i.String() }

type Issuer struct {
	issuer   capability.CapabilityIssuer
	verifier capability.CapabilityVerifier
	entropy  io.Reader
	mu       sync.Mutex
}

func (*Issuer) String() string     { return "dispatchruntime.Issuer{private:[REDACTED]}" }
func (i *Issuer) GoString() string { return i.String() }

func NewIssuer(
	issuer capability.CapabilityIssuer,
	verifier capability.CapabilityVerifier,
	entropy io.Reader,
) (*Issuer, error) {
	if issuer.KeyID() == "" || verifier.KeyID() == "" ||
		issuer.KeyID() != verifier.KeyID() || verifier.ExecutorID() == "" {
		return nil, ErrInvalidConfiguration
	}
	if entropy == nil {
		entropy = rand.Reader
	}
	return &Issuer{issuer: issuer, verifier: verifier, entropy: entropy}, nil
}

func (i *Issuer) Issue(claim Claim, validity time.Duration) (IssuedCapability, error) {
	if i == nil || i.entropy == nil || i.issuer.KeyID() == "" || i.verifier.KeyID() == "" {
		return IssuedCapability{}, ErrInvalidConfiguration
	}
	if claim.RecoveryOnly() {
		return IssuedCapability{}, ErrContractRejected
	}
	issuedAt, notBefore, expiresAt, err := claim.capabilityWindow(validity)
	if err != nil {
		if err == ErrLeaseLost {
			return IssuedCapability{}, ErrLeaseLost
		}
		return IssuedCapability{}, ErrContractRejected
	}
	capabilityID, nonce, err := i.identifiers()
	if err != nil {
		return IssuedCapability{}, err
	}
	job := claim.Job()
	common := capability.Common{
		CapabilityID: capabilityID, JobID: job.jobID, ActionID: job.actionID,
		PolicyID: job.policyID, PolicyVersion: job.policyVersion, TargetIPv4: job.targetIPv4,
		EvidenceSnapshotDigest:   job.evidenceSnapshotDigest,
		ValidationSnapshotDigest: job.validationSnapshotDigest,
		AuthorizationDigest:      job.authorizationDigest, ActorID: job.actorID,
		ReasonDigest: job.reasonDigest, OwnedSchemaDigest: job.ownedSchemaDigest,
		IssuedAt: issuedAt, NotBefore: notBefore, ExpiresAt: expiresAt, Nonce: nonce,
	}
	var checked capability.CheckedCapability
	switch job.operation {
	case capability.OperationAdd:
		if job.kind != "dispatch_add" || job.hasOriginalAddDigest {
			return IssuedCapability{}, ErrContractRejected
		}
		checked, err = capability.CheckAdd(capability.Add{Common: common, CanonicalCommand: job.artifact})
	case capability.OperationRevoke:
		if job.kind != "dispatch_revoke" || !job.hasOriginalAddDigest {
			return IssuedCapability{}, ErrContractRejected
		}
		checked, err = capability.CheckRevoke(capability.Revoke{
			Common: common, OriginalAddDigest: job.originalAddDigest, CanonicalDelete: job.artifact,
		})
	case capability.OperationInspect:
		if job.kind != "dispatch_inspect" || !job.hasOriginalAddDigest {
			return IssuedCapability{}, ErrContractRejected
		}
		artifact, parseErr := decodeInspectArtifact(job.artifact)
		if parseErr != nil {
			return IssuedCapability{}, ErrContractRejected
		}
		checked, err = capability.CheckInspect(capability.Inspect{
			Common: common, OriginalAddDigest: job.originalAddDigest, Artifact: artifact,
		})
	default:
		return IssuedCapability{}, ErrContractRejected
	}
	if err != nil || !bytes.Equal(checked.ArtifactBytes(), job.artifact) ||
		checked.Value().ArtifactDigest != job.artifactDigest {
		return IssuedCapability{}, ErrContractRejected
	}
	signed, err := i.issuer.Sign(checked)
	if err != nil {
		return IssuedCapability{}, ErrContractRejected
	}
	verified, err := i.verifier.Verify(signed)
	if err != nil || verified.Digest() != checked.Digest() {
		return IssuedCapability{}, ErrContractRejected
	}
	return IssuedCapability{Signed: signed, Verified: verified}, nil
}

func (i *Issuer) identifiers() (string, string, error) {
	var raw [32]byte
	i.mu.Lock()
	_, err := io.ReadFull(i.entropy, raw[:])
	i.mu.Unlock()
	if err != nil {
		clear(raw[:])
		return "", "", ErrEntropyUnavailable
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	id := fmt.Sprintf("%08x-%04x-%04x-%04x-%012x",
		raw[0:4], raw[4:6], raw[6:8], raw[8:10], raw[10:16])
	nonce := base64.RawURLEncoding.EncodeToString(raw[16:])
	clear(raw[:])
	return id, nonce, nil
}

type inspectArtifactWire struct {
	ActionID          string `json:"action_id"`
	Operation         string `json:"operation"`
	OriginalAddDigest string `json:"original_add_digest"`
	OwnedSchemaDigest string `json:"owned_schema_digest"`
	Purpose           string `json:"purpose"`
	SchemaVersion     string `json:"schema_version"`
	TargetIPv4        string `json:"target_ipv4"`
}

func decodeInspectArtifact(data []byte) (capability.InspectArtifact, error) {
	if len(data) == 0 || len(data) > capability.MaxArtifactBytes {
		return capability.InspectArtifact{}, ErrContractRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var wire inspectArtifactWire
	if err := decoder.Decode(&wire); err != nil {
		return capability.InspectArtifact{}, ErrContractRejected
	}
	if decoder.Decode(&struct{}{}) != io.EOF || wire.Operation != "inspect" {
		return capability.InspectArtifact{}, ErrContractRejected
	}
	return capability.InspectArtifact{
		SchemaVersion: wire.SchemaVersion, ActionID: wire.ActionID,
		TargetIPv4: wire.TargetIPv4, OriginalAddDigest: wire.OriginalAddDigest,
		OwnedSchemaDigest: wire.OwnedSchemaDigest, Purpose: wire.Purpose,
	}, nil
}
