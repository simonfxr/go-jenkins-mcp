package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/google/jsonschema-go/jsonschema"
)

// jsonschemaForExt builds a JSON Schema for T using the base generator
// (which picks up descriptions from `jsonschema` struct tags) and enriches it
// with defaults from `default` struct tags.
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

	// VisibleFields also yields the promoted fields of embedded structs.
	for _, f := range reflect.VisibleFields(t) {
		if f.PkgPath != "" || f.Anonymous { // unexported, or the embedded struct itself
			continue
		}
		jsonTag := f.Tag.Get("json")
		if jsonTag == "-" {
			continue
		}
		name, _, _ := strings.Cut(jsonTag, ",")
		if name == "" {
			name = f.Name
		}

		p, ok := sch.Properties[name]
		if !ok || p == nil {
			// Ensure a schema exists so we can annotate it
			p = &jsonschema.Schema{}
			sch.Properties[name] = p
		}

		if def := f.Tag.Get("default"); def != "" {
			p.Default = parseDefault(f.Type, def)
		}
	}

	return sch
}

// parseDefault converts a `default` struct tag value into a JSON literal
// matching the field type. It panics on unsupported types or malformed
// values, since both indicate a programming error in the tool definitions.
func parseDefault(typ reflect.Type, def string) json.RawMessage {
	if typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	var (
		v   any
		err error
	)
	switch typ.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v, err = strconv.ParseInt(def, 10, typ.Bits())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		v, err = strconv.ParseUint(def, 10, typ.Bits())
	case reflect.Float32, reflect.Float64:
		v, err = strconv.ParseFloat(def, typ.Bits())
	case reflect.Bool:
		v, err = strconv.ParseBool(def)
	case reflect.String:
		v = def
	default:
		panic(fmt.Errorf("unsupported type %s for default value", typ))
	}
	if err != nil {
		panic(fmt.Errorf("failed to parse default %q as %s: %w", def, typ, err))
	}
	bs, err := json.Marshal(v)
	if err != nil {
		panic(err) // unreachable
	}
	return bs
}
