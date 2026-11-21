package test

// Requirement: message-broker message payloads follow publisher-owned JSON
// Schemas (admin-panel as publisher of its rejection audit and as requester
// of team-registry, flow-registry and task-manager).

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"
)

// ownerOps are the responder schemas admin-panel reads (rule 17 names).
var ownerOps = []struct {
	owner, op, method, path string
	body                    any
	reply                   any
}{
	{"team-registry", "admin.create", http.MethodPost, "/admin/teams", map[string]any{"team_name": "alpha", "default_image": validImage}, teamBody()},
	{"team-registry", "admin.get", http.MethodGet, "/admin/teams/3", nil, teamBody()},
	{"team-registry", "admin.update", http.MethodPatch, "/admin/teams/3", map[string]any{"default_image": validImage}, teamBody()},
	{"team-registry", "admin.archive", http.MethodPost, "/admin/teams/3/archive", nil, teamBody()},
	{"flow-registry", "admin.tags", http.MethodGet, "/admin/tags?team_id=3&tag=openhands&limit=1", nil,
		map[string]any{"items": []any{map[string]any{"team_id": 3, "flow_id": 1, "execution_tag": "openhands"}}, "next": map[string]any{"team_id": 3, "execution_tag": "openhands", "flow_id": 1}}},
	{"task-manager", "admin.list-tasks", http.MethodGet, "/admin/tasks?team_id=3&state=pending&tag=openhands&flow_id=12&limit=1", nil,
		map[string]any{"items": []any{taskItem(3, 1)}, "next": map[string]any{"ingested_at": "2026-11-07T10:00:00.000Z", "team_id": 3, "task_id": 1}}},
}

func teamBody() map[string]any {
	return map[string]any{"team_id": 3, "team_name": "alpha", "default_image": validImage, "ingested_at": "2026-11-07T10:00:00.000Z", "archived_at": nil}
}

func compileFile(t *testing.T, path string) *jsonschema.Schema {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("publisher schema %s is missing: %v", path, err)
	}
	c := jsonschema.NewCompiler()
	s, err := c.Compile(path)
	if err != nil {
		t.Fatalf("compile %s: %v", path, err)
	}
	return s
}

func validateWith(t *testing.T, s *jsonschema.Schema, raw []byte) error {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return s.Validate(v)
}

// Scenario: Publisher message violates its own schema.
func TestV0048AdminPanelPublisherMessageViolatesItsOwnSchema(t *testing.T) {
	e := newEnv(t)
	e.do(http.MethodGet, "/admin/teams/3", e.is.sign(e.is.claims("ops", "none")), nil)
	pub := e.broker.publishedList()
	if len(pub) != 1 {
		t.Fatalf("%d messages", len(pub))
	}
	good := pub[0].Body
	if err := validateAudit(t, good); err != nil {
		t.Fatalf("published message is invalid: %v", err)
	}
	var m map[string]any
	_ = json.Unmarshal(good, &m)
	broken := map[string]func(map[string]any){
		"without actor_subject":  func(m map[string]any) { delete(m, "actor_subject") },
		"with team_id":           func(m map[string]any) { m["team_id"] = 3 },
		"with a token field":     func(m map[string]any) { m["jwt"] = "eyJ" },
		"string resource_id":     func(m map[string]any) { m["resource_id"] = "3" },
		"operator actor":         func(m map[string]any) { m["actor_type"] = "operator" },
		"succeeded outcome":      func(m map[string]any) { m["outcome"] = "succeeded" },
		"zero publisher_seq":     func(m map[string]any) { m["publisher_seq"] = 0 },
		"other publisher":        func(m map[string]any) { m["publisher"] = "team-registry" },
		"timestamp without msec": func(m map[string]any) { m["occurred_at"] = "2026-11-07T10:00:00Z" },
	}
	for name, f := range broken {
		c := map[string]any{}
		for k, v := range m {
			c[k] = v
		}
		f(c)
		raw, _ := json.Marshal(c)
		if validateAudit(t, raw) == nil {
			t.Fatalf("message %s validates; the schema must reject it", name)
		}
	}
	// The message fails every other action's schema: each file pins its action
	// and resource type.
	for _, a := range auditActions {
		if a != "team-get" && validateAuditAs(t, a, good) == nil {
			t.Fatalf("a team-get message validates against audit.%s.schema.json", a)
		}
	}
	// Every action has its own schema file, and its examples are valid.
	for _, a := range auditActions {
		var doc struct {
			Examples []json.RawMessage `json:"examples"`
		}
		data, err := os.ReadFile(schemaPath(a))
		if err != nil {
			t.Fatalf("schema for %s: %v", a, err)
		}
		if err := json.Unmarshal(data, &doc); err != nil || len(doc.Examples) == 0 {
			t.Fatalf("audit.%s.schema.json has no examples", a)
		}
		for _, ex := range doc.Examples {
			if err := validateAuditAs(t, a, ex); err != nil {
				t.Fatalf("audit.%s.schema.json example invalid: %v", a, err)
			}
		}
	}
}

// Scenario: Consumer contract test reads the publisher schema (admin-panel
// is the requester; the responders own the request and reply schemas).
func TestV0048AdminPanelConsumerContractTestReadsThePublisherSchema(t *testing.T) {
	fixtureDir := os.Getenv("FLOWAI_CONTRACT_FIXTURE_DIR")
	if fixtureDir == "" {
		t.Fatal("FLOWAI_CONTRACT_FIXTURE_DIR must point to the staged publisher schemas")
	}
	for _, op := range ownerOps {
		t.Run(op.owner+"."+op.op, func(t *testing.T) {
			dir := filepath.Join(fixtureDir, "svc", op.owner, "schemas")
			reqSchema := compileFile(t, filepath.Join(dir, op.op+".request.schema.json"))
			replySchema := compileFile(t, filepath.Join(dir, op.op+".reply.schema.json"))
			errSchema := compileFile(t, filepath.Join(dir, "error.reply.schema.json"))

			replyRaw, _ := json.Marshal(op.reply)
			if err := validateWith(t, replySchema, replyRaw); err != nil {
				t.Fatalf("the reply admin-panel handles is not valid for %s: %v", op.owner, err)
			}
			e := newEnv(t)
			subject := op.owner + "." + "admin." + op.op[len("admin."):] + ".pub"
			e.broker.on(subject, func(string, map[string]string, []byte) (reply, error) { return replyOf(200, op.reply), nil })
			res := e.do(op.method, op.path, e.is.adminToken("a"), op.body)
			if res.Status != 200 {
				t.Fatalf("admin-panel did not accept a valid %s reply: %d %s", op.op, res.Status, res.Raw)
			}
			reqs := e.broker.requestList()
			if len(reqs) != 1 {
				t.Fatalf("%d requests", len(reqs))
			}
			if err := validateWith(t, reqSchema, reqs[0].Body); err != nil {
				t.Fatalf("admin-panel's request violates %s's request schema: %v\n%s", op.owner, err, reqs[0].Body)
			}
			// Second page: the request with the continuation position is valid too.
			if pg := res.JSON["page"]; pg != nil {
				next, _ := pg.(map[string]any)["next_cursor"].(string)
				if next == "" {
					t.Fatal("no next_cursor for a reply with next")
				}
				e.do(op.method, op.path+"&cursor="+next, e.is.adminToken("a"), nil)
				reqs = e.broker.requestList()
				if err := validateWith(t, reqSchema, reqs[len(reqs)-1].Body); err != nil {
					t.Fatalf("continuation request violates the request schema: %v\n%s", err, reqs[len(reqs)-1].Body)
				}
			}
			errRaw, _ := json.Marshal(map[string]any{"code": "invalid_request", "message": "m", "request_id": 5})
			if err := validateWith(t, errSchema, errRaw); err != nil {
				t.Fatalf("the error shape admin-panel returns unchanged is not %s's: %v", op.owner, err)
			}
		})
	}
}

// Scenario: Schema change selects its consumers. The standalone projection
// preserves the matching declarations from Gitea's qa-e2e/scripts/shared-test-inputs.json.
func TestV0048AdminPanelSchemaChangeSelectsItsConsumers(t *testing.T) {
	data, err := os.ReadFile(filepath.Join(serviceDir(), "qualification", "admin-panel-declarations.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Schemas map[string][]string `json:"schemas"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	has := func(path, svc string) bool {
		for _, s := range doc.Schemas[path] {
			if s == svc {
				return true
			}
		}
		return false
	}
	for _, a := range auditActions {
		own := "svc/admin-panel/schemas/audit." + a + ".schema.json"
		if !has(own, "admin-panel") || !has(own, "audit") {
			t.Fatalf("%s must select admin-panel and its consumer audit: %v", own, doc.Schemas[own])
		}
	}
	for _, op := range ownerOps {
		for _, kind := range []string{"request", "reply"} {
			p := "svc/" + op.owner + "/schemas/" + op.op + "." + kind + ".schema.json"
			if !has(p, "admin-panel") {
				t.Fatalf("%s does not declare admin-panel as a consumer: %v", p, doc.Schemas[p])
			}
		}
	}
}
