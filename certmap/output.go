package certmap

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

type Rotation struct {
	SPKIPin string   `json:"spkiPin"`
	Before  []string `json:"before"`
	After   []string `json:"after"`
}
type Difference struct {
	Schema       string     `json:"schema"`
	BeforeSHA256 string     `json:"beforeSha256"`
	AfterSHA256  string     `json:"afterSha256"`
	Added        []string   `json:"added"`
	Removed      []string   `json:"removed"`
	ReissuedKeys []Rotation `json:"reissuedKeys"`
	Notices      []string   `json:"notices"`
}

// Diff compares DER identities, so PEM wrapping, order and duplicate blocks do not matter.
func Diff(before, after Bundle) Difference {
	result := Difference{Schema: "rudy-certmap/diff/v1", BeforeSHA256: before.SHA256, AfterSHA256: after.SHA256, Added: []string{}, Removed: []string{}, ReissuedKeys: []Rotation{},
		Notices: []string{"Differences describe supplied inventories, not live deployment state.", "Reissued keys share SPKI bytes; this does not prove issuer, owner or private-key continuity."}}
	a, b := map[string]bool{}, map[string]bool{}
	ak, bk := map[string][]string{}, map[string][]string{}
	for _, c := range before.Certificates {
		a[ID(c)] = true
		ak[SPKIPin(c)] = append(ak[SPKIPin(c)], ID(c))
	}
	for _, c := range after.Certificates {
		b[ID(c)] = true
		bk[SPKIPin(c)] = append(bk[SPKIPin(c)], ID(c))
	}
	for id := range a {
		if !b[id] {
			result.Removed = append(result.Removed, id)
		}
	}
	for id := range b {
		if !a[id] {
			result.Added = append(result.Added, id)
		}
	}
	sort.Strings(result.Added)
	sort.Strings(result.Removed)
	for pin, old := range ak {
		if next, ok := bk[pin]; ok {
			old = sorted(old)
			next = sorted(next)
			if strings.Join(old, "/") != strings.Join(next, "/") {
				result.ReissuedKeys = append(result.ReissuedKeys, Rotation{pin, old, next})
			}
		}
	}
	sort.Slice(result.ReissuedKeys, func(i, j int) bool { return result.ReissuedKeys[i].SPKIPin < result.ReissuedKeys[j].SPKIPin })
	return result
}

func JSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// DOT renders cryptographic issuer edges, not authenticated deployment/trust claims.
func DOT(report Report) string {
	var out strings.Builder
	out.WriteString("digraph certmap {\n  rankdir=LR;\n  node [shape=box];\n")
	for _, c := range report.Certificates {
		label := c.Subject + "\n" + c.ID[:16] + "\n" + c.NotAfter.Format("2006-01-02")
		fmt.Fprintf(&out, "  %s [label=%s];\n", strconv.Quote(c.ID), strconv.Quote(label))
	}
	for _, edge := range report.SignatureEdges {
		fmt.Fprintf(&out, "  %s -> %s [label=\"signature\"];\n", strconv.Quote(edge.Child), strconv.Quote(edge.Parent))
	}
	out.WriteString("}\n")
	return out.String()
}

var ruleNames = map[string]string{"CERT001": "Expired certificate", "CERT002": "Certificate not yet valid", "CERT003": "Certificate expires soon",
	"CERT004": "Weak or unsupported public key", "CERT005": "Legacy signature algorithm", "CERT006": "Invalid CA declaration", "CERT007": "Trust policy verification failed", "CERT008": "Missing server identity SAN"}

// SARIF has no invented source locations. Certificate IDs and evaluation context
// are retained in result properties; fingerprints identify rule/certificate pairs.
func SARIF(report Report) map[string]any {
	rules := []any{}
	ids := make([]string, 0, len(ruleNames))
	for id := range ruleNames {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		rules = append(rules, map[string]any{"id": id, "shortDescription": map[string]string{"text": ruleNames[id]}})
	}
	results := []any{}
	for _, f := range report.Findings {
		results = append(results, map[string]any{"ruleId": f.Rule, "level": f.Level, "message": map[string]string{"text": f.Message},
			"partialFingerprints": map[string]string{"certmap/v1": digest([]byte(f.Rule + "/" + f.Certificate))},
			"properties":          map[string]any{"certificateSha256": f.Certificate, "evaluationTime": report.At, "dnsName": report.DNSName, "purpose": report.Purpose}})
	}
	return map[string]any{"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0", "runs": []any{map[string]any{
		"tool":    map[string]any{"driver": map[string]any{"name": "Rudy CertMap", "version": Version, "informationUri": "https://github.com/r4venrudy/rudy-certmap", "rules": rules}},
		"results": results, "properties": map[string]any{"inputs": report.Inputs, "coverageNotices": report.Notices}}}}
}
