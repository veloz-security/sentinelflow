package correlation

import (
	"sort"
	"time"

	"github.com/devwooops/sentinelflow/internal/detection"
)

// Correlate returns deterministic connected temporal components. Only the
// canonical source and a direct <=5 minute temporal relation create an edge;
// service, classification, account, and path context never establish identity.
func Correlate(signals []detection.Signal) ([]Group, error) {
	values, err := normalizeSignals(signals)
	if err != nil {
		return nil, err
	}
	if len(values) == 0 {
		return []Group{}, nil
	}

	groups := make([]Group, 0)
	component := []detection.Signal{values[0]}
	componentEnd := values[0].WindowEnd
	for _, signal := range values[1:] {
		previous := component[len(component)-1]
		if signal.SourceIP == previous.SourceIP && !signal.WindowStart.After(componentEnd.Add(MaximumSignalGap)) {
			component = append(component, signal)
			if signal.WindowEnd.After(componentEnd) {
				componentEnd = signal.WindowEnd
			}
			continue
		}
		group, err := buildGroup(component)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
		component = []detection.Signal{signal}
		componentEnd = signal.WindowEnd
	}
	group, err := buildGroup(component)
	if err != nil {
		return nil, err
	}
	groups = append(groups, group)

	sort.Slice(groups, func(i, j int) bool {
		if groups[i].SourceIP != groups[j].SourceIP {
			return groups[i].SourceIP < groups[j].SourceIP
		}
		if !groups[i].WindowStart.Equal(groups[j].WindowStart) {
			return groups[i].WindowStart.Before(groups[j].WindowStart)
		}
		return groups[i].Snapshot.Digest() < groups[j].Snapshot.Digest()
	})
	return groups, nil
}

func buildGroup(signals []detection.Signal) (Group, error) {
	snapshot, err := buildEvidenceSnapshot(signals)
	if err != nil {
		return Group{}, err
	}
	values := cloneSignals(signals)
	sortSignals(values)
	relations := buildRelations(values)
	return Group{
		SourceIP:    snapshot.SourceIP(),
		WindowStart: snapshot.WindowStart(),
		WindowEnd:   snapshot.WindowEnd(),
		Snapshot:    snapshot,
		signals:     values,
		relations:   relations,
	}, nil
}

func buildRelations(signals []detection.Signal) []Relation {
	result := make([]Relation, 0)
	for leftIndex := 0; leftIndex < len(signals); leftIndex++ {
		for rightIndex := leftIndex + 1; rightIndex < len(signals); rightIndex++ {
			left := signals[leftIndex]
			right := signals[rightIndex]
			if left.SourceIP != right.SourceIP {
				continue
			}
			temporal, related := temporalRelation(left, right)
			if !related {
				continue
			}
			result = append(result, makeRelation(left, right, temporal))
		}
	}
	sortRelations(result)
	return result
}

func temporalRelation(left, right detection.Signal) (TemporalReason, bool) {
	if intervalsOverlap(left.WindowStart, left.WindowEnd, right.WindowStart, right.WindowEnd) {
		return TemporalWindowOverlap, true
	}
	var gap time.Duration
	if left.WindowEnd.Before(right.WindowStart) {
		gap = right.WindowStart.Sub(left.WindowEnd)
	} else {
		gap = left.WindowStart.Sub(right.WindowEnd)
	}
	if gap <= MaximumSignalGap {
		return TemporalWithinFiveMinutes, true
	}
	return "", false
}

func intervalsOverlap(leftStart, leftEnd, rightStart, rightEnd time.Time) bool {
	return !leftStart.After(rightEnd) && !rightStart.After(leftEnd)
}

func makeRelation(left, right detection.Signal, temporal TemporalReason) Relation {
	if right.SignalID < left.SignalID {
		left, right = right, left
	}
	supporting := []SupportingReason{SupportingAccountIdentityMinimized, SupportingPathIdentityMinimized}
	if left.ServiceLabel == right.ServiceLabel {
		supporting = append(supporting, SupportingSameService)
	} else {
		supporting = append(supporting, SupportingDifferentService)
	}
	if left.RuleID == right.RuleID {
		supporting = append(supporting, SupportingSameRule)
	} else {
		supporting = append(supporting, SupportingDifferentRule)
	}
	sort.Slice(supporting, func(i, j int) bool { return supporting[i] < supporting[j] })
	return Relation{
		LeftSignalID:      left.SignalID,
		RightSignalID:     right.SignalID,
		IdentityReason:    IdentitySameCanonicalSource,
		TemporalReason:    temporal,
		SupportingReasons: supporting,
	}
}

func sortRelations(values []Relation) {
	sort.Slice(values, func(i, j int) bool {
		if values[i].LeftSignalID != values[j].LeftSignalID {
			return values[i].LeftSignalID < values[j].LeftSignalID
		}
		if values[i].RightSignalID != values[j].RightSignalID {
			return values[i].RightSignalID < values[j].RightSignalID
		}
		return values[i].TemporalReason < values[j].TemporalReason
	})
}
