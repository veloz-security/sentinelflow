package nftbootstrap

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/devwooops/sentinelflow/internal/enforcement/nftvalidate"
)

// rulesetSnapshot separates the executor-owned table from every foreign
// object without interpreting or authorizing the foreign objects. Foreign
// state is retained only as bounded canonical comparison bytes so bootstrap
// can prove that its pinned transaction did not alter it.
type rulesetSnapshot struct {
	metainfo         metainfoWire
	ownedEntries     []nftEntry
	ownedTableExists bool
	ownedObjectCount int
	tableCount       int
	foreignCanonical []byte
}

type rawNFTDocument struct {
	NFTables []json.RawMessage `json:"nftables"`
}

func parseRulesetSnapshot(data []byte, code ErrorCode) (rulesetSnapshot, error) {
	if len(data) == 0 || len(data) > MaxProcessOutput || validateUniqueJSONKeys(data) != nil {
		return rulesetSnapshot{}, reject(code)
	}
	var document rawNFTDocument
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil || len(document.NFTables) == 0 {
		return rulesetSnapshot{}, reject(code)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return rulesetSnapshot{}, reject(code)
	}

	first, err := decodeSnapshotEntry(document.NFTables[0], code)
	if err != nil || !onlyMetainfo(first) || !validMetainfo(first.Metainfo) {
		return rulesetSnapshot{}, reject(code)
	}
	snapshot := rulesetSnapshot{metainfo: *first.Metainfo}
	foreign := make([][]byte, 0, len(document.NFTables)-1)
	for _, raw := range document.NFTables[1:] {
		kind, payload, envelopeErr := decodeEntryEnvelope(raw)
		if envelopeErr != nil {
			return rulesetSnapshot{}, reject(code)
		}
		if kind == "metainfo" {
			return rulesetSnapshot{}, reject(code)
		}
		if kind == "table" {
			snapshot.tableCount++
		}
		if entryOwnsSentinelFlowTable(kind, payload) {
			entry, decodeErr := decodeSnapshotEntry(raw, code)
			if decodeErr != nil {
				return rulesetSnapshot{}, reject(code)
			}
			if kind == "table" && (!onlyTable(entry) || !validInventoryTable(entry.Table) || snapshot.ownedTableExists) {
				return rulesetSnapshot{}, reject(code)
			}
			snapshot.ownedEntries = append(snapshot.ownedEntries, entry)
			snapshot.ownedObjectCount++
			if kind == "table" {
				snapshot.ownedTableExists = true
			}
			continue
		}
		canonical, canonicalErr := canonicalForeignEntry(raw)
		if canonicalErr != nil {
			return rulesetSnapshot{}, reject(code)
		}
		foreign = append(foreign, canonical)
	}
	snapshot.foreignCanonical = joinCanonicalEntries(foreign)
	return snapshot, nil
}

func decodeSnapshotEntry(raw []byte, code ErrorCode) (nftEntry, error) {
	var entry nftEntry
	if strictDecode(raw, &entry) != nil {
		return nftEntry{}, reject(code)
	}
	return entry, nil
}

func decodeEntryEnvelope(raw []byte) (string, json.RawMessage, error) {
	var envelope map[string]json.RawMessage
	if strictDecode(raw, &envelope) != nil || len(envelope) != 1 {
		return "", nil, reject(ErrorLiveReadbackInvalid)
	}
	for kind, payload := range envelope {
		if kind == "" || len(payload) == 0 {
			return "", nil, reject(ErrorLiveReadbackInvalid)
		}
		return kind, append(json.RawMessage(nil), payload...), nil
	}
	return "", nil, reject(ErrorLiveReadbackInvalid)
}

func entryOwnsSentinelFlowTable(kind string, payload []byte) bool {
	var identity map[string]json.RawMessage
	if strictDecode(payload, &identity) != nil {
		return false
	}
	family, familyOK := rawJSONString(identity["family"])
	if !familyOK || family != nftvalidate.Family {
		return false
	}
	if kind == "table" {
		name, nameOK := rawJSONString(identity["name"])
		return nameOK && name == nftvalidate.Table
	}
	table, tableOK := rawJSONString(identity["table"])
	return tableOK && table == nftvalidate.Table
}

func rawJSONString(raw []byte) (string, bool) {
	if len(raw) == 0 {
		return "", false
	}
	var value string
	if strictDecode(raw, &value) != nil {
		return "", false
	}
	return value, true
}

func canonicalForeignEntry(raw []byte) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, reject(ErrorLiveReadbackInvalid)
	}
	return json.Marshal(value)
}

func joinCanonicalEntries(entries [][]byte) []byte {
	var result bytes.Buffer
	result.WriteByte('[')
	for index, entry := range entries {
		if index > 0 {
			result.WriteByte(',')
		}
		result.Write(entry)
	}
	result.WriteByte(']')
	return result.Bytes()
}
