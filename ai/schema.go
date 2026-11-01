package ai

import (
	"encoding/json"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
)

// ValidateJSON checks doc against a JSON Schema. It supports the subset that
// structured-output APIs accept: type (single or list), enum, const,
// properties, required, additionalProperties (bool or schema), items,
// minItems, maxItems, minLength, maxLength, pattern, minimum, maximum, anyOf,
// oneOf and local "#/$defs/..." or "#/definitions/..." references. Unknown
// keywords are ignored. A nil error means doc conforms.
func ValidateJSON(schema, doc json.RawMessage) error {
	var s any
	if err := json.Unmarshal(schema, &s); err != nil {
		return fmt.Errorf("invalid schema: %w", err)
	}
	var d any
	if err := json.Unmarshal(doc, &d); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return validateNode(s, s, d, "$", 0)
}

func validateNode(root, schema, v any, path string, depth int) error {
	if depth > 64 {
		return fmt.Errorf("%s: schema nesting too deep", path)
	}
	sm, ok := schema.(map[string]any)
	if !ok { // true / unknown: accept
		if b, isBool := schema.(bool); isBool && !b {
			return fmt.Errorf("%s: no value is allowed here", path)
		}
		return nil
	}
	if ref, ok := sm["$ref"].(string); ok {
		target, err := resolveRef(root, ref)
		if err != nil {
			return fmt.Errorf("%s: %v", path, err)
		}
		return validateNode(root, target, v, path, depth+1)
	}
	if t, ok := sm["type"]; ok {
		if !typeMatches(t, v) {
			return fmt.Errorf("%s: expected %s, got %s", path, typeString(t), jsonType(v))
		}
	}
	if e, ok := sm["enum"].([]any); ok {
		found := false
		for _, x := range e {
			if jsonEqual(x, v) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("%s: value %s is not one of the allowed values", path, compact(v))
		}
	}
	if c, ok := sm["const"]; ok && !jsonEqual(c, v) {
		return fmt.Errorf("%s: value must be %s", path, compact(c))
	}
	if subs, ok := sm["anyOf"].([]any); ok {
		if !anySub(root, subs, v, path, depth) {
			return fmt.Errorf("%s: does not match any allowed alternative", path)
		}
	}
	if subs, ok := sm["oneOf"].([]any); ok {
		n := 0
		for _, sub := range subs {
			if validateNode(root, sub, v, path, depth+1) == nil {
				n++
			}
		}
		if n != 1 {
			return fmt.Errorf("%s: must match exactly one alternative, matched %d", path, n)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		return validateObject(root, sm, x, path, depth)
	case []any:
		return validateArray(root, sm, x, path, depth)
	case string:
		n := len([]rune(x))
		if m, ok := num(sm["minLength"]); ok && float64(n) < m {
			return fmt.Errorf("%s: shorter than %v characters", path, m)
		}
		if m, ok := num(sm["maxLength"]); ok && float64(n) > m {
			return fmt.Errorf("%s: longer than %v characters", path, m)
		}
		if p, ok := sm["pattern"].(string); ok {
			re, err := regexp.Compile(p)
			if err == nil && !re.MatchString(x) {
				return fmt.Errorf("%s: does not match pattern %q", path, p)
			}
		}
	case float64:
		if m, ok := num(sm["minimum"]); ok && x < m {
			return fmt.Errorf("%s: %v is below minimum %v", path, x, m)
		}
		if m, ok := num(sm["maximum"]); ok && x > m {
			return fmt.Errorf("%s: %v is above maximum %v", path, x, m)
		}
	}
	return nil
}

func anySub(root any, subs []any, v any, path string, depth int) bool {
	for _, sub := range subs {
		if validateNode(root, sub, v, path, depth+1) == nil {
			return true
		}
	}
	return false
}

func validateObject(root any, sm map[string]any, obj map[string]any, path string, depth int) error {
	props, _ := sm["properties"].(map[string]any)
	if req, ok := sm["required"].([]any); ok {
		for _, r := range req {
			if name, ok := r.(string); ok {
				if _, present := obj[name]; !present {
					return fmt.Errorf("%s: missing required property %q", path, name)
				}
			}
		}
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		child := path + "." + k
		if ps, ok := props[k]; ok {
			if err := validateNode(root, ps, obj[k], child, depth+1); err != nil {
				return err
			}
			continue
		}
		switch ap := sm["additionalProperties"].(type) {
		case bool:
			if !ap {
				return fmt.Errorf("%s: unexpected property %q", path, k)
			}
		case map[string]any:
			if err := validateNode(root, ap, obj[k], child, depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func validateArray(root any, sm map[string]any, arr []any, path string, depth int) error {
	if m, ok := num(sm["minItems"]); ok && float64(len(arr)) < m {
		return fmt.Errorf("%s: fewer than %v items", path, m)
	}
	if m, ok := num(sm["maxItems"]); ok && float64(len(arr)) > m {
		return fmt.Errorf("%s: more than %v items", path, m)
	}
	if items, ok := sm["items"]; ok {
		for i, el := range arr {
			if err := validateNode(root, items, el, fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

func resolveRef(root any, ref string) (any, error) {
	if !strings.HasPrefix(ref, "#/") {
		return nil, fmt.Errorf("unsupported $ref %q", ref)
	}
	cur := root
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("unresolvable $ref %q", ref)
		}
		if cur, ok = m[part]; !ok {
			return nil, fmt.Errorf("unresolvable $ref %q", ref)
		}
	}
	return cur, nil
}

func typeMatches(t, v any) bool {
	switch tt := t.(type) {
	case string:
		return oneType(tt, v)
	case []any:
		for _, x := range tt {
			if s, ok := x.(string); ok && oneType(s, v) {
				return true
			}
		}
	}
	return false
}

func oneType(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number":
		_, ok := v.(float64)
		return ok
	case "integer":
		f, ok := v.(float64)
		return ok && f == math.Trunc(f)
	}
	return false
}

func jsonType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case float64:
		return "number"
	case string:
		return "string"
	case []any:
		return "array"
	case map[string]any:
		return "object"
	}
	return "unknown"
}

func typeString(t any) string {
	b, _ := json.Marshal(t)
	return string(b)
}

func compact(v any) string {
	b, _ := json.Marshal(v)
	if len(b) > 80 {
		return string(b[:80]) + "..."
	}
	return string(b)
}

func jsonEqual(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return string(x) == string(y)
}

func num(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}
