package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// CompleteJSON asks p for a JSON answer and decodes it into T. When req.Schema
// is set the decoded document is first checked against it (see ValidateJSON),
// then validate (optional) is called. If parsing or validation fails, the
// request is repeated once with the bad answer and the error appended to the
// conversation; a second failure returns an error wrapping ErrInvalidOutput.
// Provider errors (including ErrRefused and ErrTruncated) are returned as is
// and are not retried. The returned Response is the last one received, with
// token counts summed over both attempts.
func CompleteJSON[T any](ctx context.Context, p Provider, req Request, validate func(T) error) (T, Response, error) {
	var zero T
	var total Response
	msgs := append([]Message(nil), req.Messages...)
	var lastErr error
	for attempt := 0; attempt < 2; attempt++ {
		r := req
		r.Messages = msgs
		resp, err := p.Complete(ctx, r)
		in, out := total.InputTokens+resp.InputTokens, total.OutputTokens+resp.OutputTokens
		total = resp
		total.InputTokens, total.OutputTokens = in, out
		if err != nil {
			return zero, total, err
		}
		v, err := decodeAndValidate(resp.Text, req.Schema, validate)
		if err == nil {
			return v, total, nil
		}
		lastErr = err
		msgs = append(msgs,
			Message{Role: "assistant", Text: resp.Text},
			Message{Role: "user", Text: "Your previous answer was rejected: " + err.Error() +
				"\nReply again with only a corrected JSON value."},
		)
	}
	return zero, total, fmt.Errorf("%w: %v", ErrInvalidOutput, lastErr)
}

func decodeAndValidate[T any](text string, schema json.RawMessage, validate func(T) error) (T, error) {
	var v T
	doc, err := ExtractJSON(text)
	if err != nil {
		return v, err
	}
	if len(schema) > 0 {
		if err := ValidateJSON(schema, doc); err != nil {
			return v, err
		}
	}
	dec := json.NewDecoder(bytes.NewReader(doc))
	if err := dec.Decode(&v); err != nil {
		return v, fmt.Errorf("decoding JSON: %w", err)
	}
	if validate != nil {
		if err := validate(v); err != nil {
			return v, err
		}
	}
	return v, nil
}

// ExtractJSON returns the JSON value in a model answer. It tolerates a
// Markdown code fence or surrounding prose, which small local models add
// despite instructions; the result is still validated by the caller.
func ExtractJSON(text string) (json.RawMessage, error) {
	s := strings.TrimSpace(text)
	if s == "" {
		return nil, errors.New("empty response")
	}
	if json.Valid([]byte(s)) {
		return json.RawMessage(s), nil
	}
	if i := strings.Index(s, "```"); i >= 0 {
		rest := s[i+3:]
		if nl := strings.IndexByte(rest, '\n'); nl >= 0 {
			rest = rest[nl+1:]
		}
		if j := strings.Index(rest, "```"); j >= 0 {
			if c := strings.TrimSpace(rest[:j]); json.Valid([]byte(c)) {
				return json.RawMessage(c), nil
			}
		}
	}
	for _, pair := range [][2]byte{{'{', '}'}, {'[', ']'}} {
		a, b := strings.IndexByte(s, pair[0]), strings.LastIndexByte(s, pair[1])
		if a >= 0 && b > a {
			if c := s[a : b+1]; json.Valid([]byte(c)) {
				return json.RawMessage(c), nil
			}
		}
	}
	return nil, errors.New("response is not valid JSON")
}
