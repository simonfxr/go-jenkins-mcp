package main

import (
	"encoding/json"
	"reflect"
	"strconv"

	"github.com/google/jsonschema-go/jsonschema"
)

// jsonschemaForExt builds a JSON Schema for T using the base generator
// and enriches it with descriptions from `mcp` struct tags and defaults
// from `default` struct tags.
func jsonschemaForExt[T any]() *jsonschema.Schema {
	sch, err := jsonschema.For[T](nil)
	if err != nil {
		panic(err)
	}

	var zero T
	t := reflect.TypeOf(zero)
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		panic("bad type")
	}

	if sch.Properties == nil {
		sch.Properties = make(map[string]*jsonschema.Schema)
	}

	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if f.PkgPath != "" { // unexported
			continue
		}
		jsonTag := f.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		name := jsonTag
		if name == "" {
			name = f.Name
		}
		if comma := indexByte(name, ','); comma >= 0 {
			name = name[:comma]
		}
		if name == "" {
			name = f.Name
		}

		p, ok := sch.Properties[name]
		if !ok || p == nil {
			// Ensure a schema exists so we can annotate it
			p = &jsonschema.Schema{}
			sch.Properties[name] = p
		}

		if desc := f.Tag.Get("mcp"); desc != "" {
			p.Description = desc
		}

		if def := f.Tag.Get("default"); def != "" {
			// Heuristically encode default literal
			if _, err := strconv.ParseInt(def, 10, 64); err == nil {
				p.Default = json.RawMessage(def)
			} else if _, err := strconv.ParseFloat(def, 64); err == nil {
				p.Default = json.RawMessage(def)
			} else if def == "true" || def == "false" {
				p.Default = json.RawMessage(def)
			} else {
				// treat as string
				b, _ := json.Marshal(def)
				p.Default = json.RawMessage(b)
			}
		}
	}

	return sch
}

// indexByte is strings.IndexByte but avoids pulling strings for this.
func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
