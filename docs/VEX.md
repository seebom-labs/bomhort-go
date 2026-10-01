# Uploading VEX to BOMHort

This is the contract between a VEX producer and BOMHort ≥ 0.7.0, as implemented in BOMHort's parser (`internal/vex/parser.go`), parsing worker (`cmd/parsing-worker/vex_scope.go`, `vex_rescue.go`) and queries (`internal/clickhouse`). The E2E suite verifies each rule below against a real BOMHort, and `bomhorttest` implements the same rules.

## 1. Every statement belongs to exactly one SBOM

BOMHort has no fleet-wide VEX. A statement only ever affects findings of the SBOM it is **scoped** to:

| Upload | Scope |
|---|---|
| `UploadVEX(ctx, name, doc, sbomID)` (`?sbom_id=`) | All statements in the document → that SBOM |
| `UploadVEX(ctx, name, doc, "")` | Per product: BOMHort resolves the product `@id` (or `identifiers.purl`) against the SBOMs' **id**, **source_repo** (normalised, so `git+https://github.com/o/r.git@v1` works), **document_namespace** and **document_name**, in that order |

A statement whose product resolves to no SBOM is stored **unscoped** (`VEXStatement.SBOMID == ""`) and suppresses nothing. BOMHort re-tries the resolution after every SBOM ingest, so uploading VEX before its SBOM is fine — it starts to apply once the SBOM is ingested.

**Recommendation:** pass the SBOM ID whenever you know it. It is unambiguous and independent of how the product is named.

## 2. Product shapes

```jsonc
// (a) Spec shape with components — recommended
"products": [{
  "@id": "<product: e.g. the repo URL or SBOM document name>",
  "subcomponents": [{ "@id": "pkg:golang/golang.org/x/net@v0.17.0" }]
}]
// → one statement per subcomponent, product_purl = the subcomponent purl

// (b) Product without subcomponents — "the product as a whole"
"products": [{ "@id": "<product>" }]
// → once scoped, product_purl = "*": covers EVERY finding with this
//   vulnerability ID in the SBOM, whichever package carries it
```

Watch out for the common "component shape" (Trivy & co.), where the vulnerable package purl is used as the product:

```jsonc
"products": [{ "@id": "pkg:golang/golang.org/x/net@v0.17.0" }]
```

- with `?sbom_id=` it is treated like (b): product-wide, `product_purl = "*"` — it then also covers other packages in that SBOM with the same vulnerability ID;
- without `?sbom_id=` the purl normally resolves to no SBOM, so the statement is inert.

Use shape (a) when a statement is about one specific package.

## 3. Matching a finding

Within its SBOM, a statement applies to a finding (`Vulnerability`) when

- `statement.vuln_id == finding.VulnID` — or one of the finding's aliases — **and**
- `statement.product_purl == finding.PURL` **or** `statement.product_purl == "*"`.

Comparison is plain string equality. **Copy `VulnID` and `PURL` verbatim from the finding**; do not normalise, re-encode, re-qualify or lower-case them. The only normalisation BOMHort applies is to vulnerability names that are URLs: `https://github.com/advisories/GHSA-xxxx` becomes `GHSA-xxxx`.

If several statements match, the one with the newest timestamp wins (statement `timestamp`, else document `timestamp`, else ingest time). A newer `affected` therefore un-suppresses an older `not_affected`.

The winning statement is reported on the finding:

| Field | Value |
|---|---|
| `VEXStatus`, `VEXJustification`, `VEXTimestamp` | from the winning statement |
| `VEXStatementID`, `VEXAuthor`, `VEXTooling` | provenance of the winning statement |
| `VEXScope` | `"sbom"` |

## 4. Upload mechanics

- Uploads require `AUTH_ENABLED=true` (`403` otherwise) and writable storage (`503` otherwise).
- The filename decides the job type, case-insensitively: `*.openvex.json` / `*.vex.json` → VEX, any other `*.json` → SBOM. `UploadVEX` refuses other names client-side; `?sbom_id=` must be a UUID and is only allowed for VEX.
- Ingestion is asynchronous: `UploadResult.Status == "pending"` with a `JobID`. Poll `Vulnerabilities` (or `SBOMVEXStatements`) until the status shows up.
- Uploading byte-identical content again returns `UploadResult.Duplicate() == true` and changes nothing. To replace a statement, upload a new document with a newer timestamp.

## 5. Minimal end-to-end example

```go
vulns, _ := c.Vulnerabilities(ctx, sbom.ID)
v := vulns[0]
doc, _ := json.Marshal(map[string]any{
	"@context":  "https://openvex.dev/ns/v0.2.0",
	"@id":       "https://example.com/vex/" + sbom.ID + "/1",
	"author":    "security@example.com",
	"timestamp": time.Now().UTC().Format(time.RFC3339),
	"version":   1,
	"statements": []any{map[string]any{
		"vulnerability": map[string]any{"name": v.VulnID},                 // verbatim
		"products": []any{map[string]any{
			"@id":           sbom.DocumentName,
			"subcomponents": []any{map[string]any{"@id": v.PURL}},          // verbatim
		}},
		"status":        "not_affected",
		"justification": "vulnerable_code_not_in_execute_path",
	}},
})
_, err := c.UploadVEX(ctx, sbom.DocumentName+".openvex.json", doc, sbom.ID)
```
