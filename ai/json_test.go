package ai

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type scripted struct {
	replies []Response
	errs    []error
	seen    []Request
}

func (s *scripted) Name() string { return "scripted" }
func (s *scripted) Complete(_ context.Context, r Request) (Response, error) {
	i := len(s.seen)
	s.seen = append(s.seen, r)
	var err error
	if i < len(s.errs) {
		err = s.errs[i]
	}
	if i >= len(s.replies) {
		return Response{}, errors.New("unexpected extra call")
	}
	return s.replies[i], err
}

type pick struct {
	Paths []string `json:"paths"`
}

func validPick(p pick) error {
	if len(p.Paths) > 2 {
		return errors.New("too many paths")
	}
	return nil
}

func rep(text string) Response { return Response{Text: text, InputTokens: 10, OutputTokens: 5} }

func TestCompleteJSONValidFirstTry(t *testing.T) {
	s := &scripted{replies: []Response{rep(`{"paths":["/a"]}`)}}
	v, resp, err := CompleteJSON(context.Background(), s, Request{Schema: pickSchema, Messages: []Message{{Role: "user", Text: "q"}}}, validPick)
	if err != nil || len(v.Paths) != 1 || len(s.seen) != 1 || resp.InputTokens != 10 {
		t.Fatalf("v=%+v err=%v calls=%d", v, err, len(s.seen))
	}
}

func TestCompleteJSONRetriesOnceThenSucceeds(t *testing.T) {
	for name, bad := range map[string]string{
		"not json":         "sure! here you go",
		"schema violation": `{"paths":"/a"}`,
		"missing required": `{}`,
		"extra property":   `{"paths":[],"why":"x"}`,
		"validator fails":  `{"paths":["/a","/b","/c"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			s := &scripted{replies: []Response{rep(bad), rep("```json\n{\"paths\":[\"/b\"]}\n```")}}
			v, resp, err := CompleteJSON(context.Background(), s, Request{Schema: pickSchema, Messages: []Message{{Role: "user", Text: "q"}}}, validPick)
			if err != nil || v.Paths[0] != "/b" {
				t.Fatalf("v=%+v err=%v", v, err)
			}
			if len(s.seen) != 2 || resp.InputTokens != 20 || resp.OutputTokens != 10 {
				t.Fatalf("calls=%d resp=%+v", len(s.seen), resp)
			}
			second := s.seen[1].Messages
			if len(second) != 3 || second[1].Role != "assistant" || second[1].Text != bad || second[2].Role != "user" ||
				!strings.Contains(second[2].Text, "rejected") {
				t.Fatalf("retry conversation = %+v", second)
			}
		})
	}
}

func TestCompleteJSONInvalidTwice(t *testing.T) {
	s := &scripted{replies: []Response{rep("nope"), rep("still nope")}}
	_, _, err := CompleteJSON[pick](context.Background(), s, Request{}, nil)
	if !errors.Is(err, ErrInvalidOutput) || len(s.seen) != 2 {
		t.Fatalf("err=%v calls=%d", err, len(s.seen))
	}
}

func TestCompleteJSONProviderErrorsNotRetried(t *testing.T) {
	for _, e := range []error{ErrRefused, ErrTruncated, errors.New("boom")} {
		s := &scripted{replies: []Response{rep("")}, errs: []error{e}}
		_, _, err := CompleteJSON[pick](context.Background(), s, Request{}, nil)
		if !errors.Is(err, e) || len(s.seen) != 1 {
			t.Fatalf("err=%v calls=%d", err, len(s.seen))
		}
	}
}

func TestCompleteJSONDoesNotMutateRequest(t *testing.T) {
	msgs := make([]Message, 1, 10)
	msgs[0] = Message{Role: "user", Text: "q"}
	s := &scripted{replies: []Response{rep("x"), rep(`{"paths":[]}`)}}
	if _, _, err := CompleteJSON[pick](context.Background(), s, Request{Messages: msgs}, nil); err != nil {
		t.Fatal(err)
	}
	if len(msgs) != 1 || msgs[:2][1].Text != "" {
		t.Fatal("caller slice mutated")
	}
}

func TestExtractJSON(t *testing.T) {
	for in, want := range map[string]string{
		`{"a":1}`:                           `{"a":1}`,
		"  [1,2]\n":                         `[1,2]`,
		"```json\n{\"a\":1}\n```":           `{"a":1}`,
		"```\n{\"a\":1}\n```":               `{"a":1}`,
		`Here: {"a":{"b":2}} hope it helps`: `{"a":{"b":2}}`,
	} {
		got, err := ExtractJSON(in)
		if err != nil || string(got) != want {
			t.Errorf("%q: got %q err %v", in, got, err)
		}
	}
	for _, in := range []string{"", "  ", "no json here", "{broken"} {
		if _, err := ExtractJSON(in); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
}

func TestValidateJSON(t *testing.T) {
	schema := `{
	  "type":"object",
	  "required":["kind","items"],
	  "additionalProperties":false,
	  "properties":{
	    "kind":{"enum":["a","b"]},
	    "n":{"type":"integer","minimum":1,"maximum":5},
	    "name":{"type":"string","minLength":2,"maxLength":4,"pattern":"^[a-z]+$"},
	    "items":{"type":"array","minItems":1,"maxItems":2,"items":{"$ref":"#/$defs/item"}},
	    "opt":{"type":["string","null"]},
	    "any":{"anyOf":[{"type":"string"},{"type":"number"}]}
	  },
	  "$defs":{"item":{"type":"object","required":["p"],"properties":{"p":{"type":"string"}}}}
	}`
	ok := []string{
		`{"kind":"a","items":[{"p":"x"}]}`,
		`{"kind":"b","n":3,"name":"abc","items":[{"p":"x"},{"p":"y"}],"opt":null,"any":1.5}`,
	}
	bad := []string{
		`[]`, `{"items":[{"p":"x"}]}`, `{"kind":"c","items":[{"p":"x"}]}`,
		`{"kind":"a","items":[]}`, `{"kind":"a","items":[{"p":"x"},{"p":"y"},{"p":"z"}]}`,
		`{"kind":"a","items":[{"q":"x"}]}`, `{"kind":"a","items":[{"p":1}]}`,
		`{"kind":"a","items":[{"p":"x"}],"extra":1}`, `{"kind":"a","n":1.5,"items":[{"p":"x"}]}`,
		`{"kind":"a","n":9,"items":[{"p":"x"}]}`, `{"kind":"a","name":"A","items":[{"p":"x"}]}`,
		`{"kind":"a","name":"abcde","items":[{"p":"x"}]}`, `{"kind":"a","opt":3,"items":[{"p":"x"}]}`,
		`{"kind":"a","any":true,"items":[{"p":"x"}]}`,
	}
	for _, d := range ok {
		if err := ValidateJSON([]byte(schema), []byte(d)); err != nil {
			t.Errorf("%s: %v", d, err)
		}
	}
	for _, d := range bad {
		if err := ValidateJSON([]byte(schema), []byte(d)); err == nil {
			t.Errorf("%s: want error", d)
		}
	}
	if err := ValidateJSON([]byte(`{`), []byte(`{}`)); err == nil {
		t.Error("bad schema accepted")
	}
}
