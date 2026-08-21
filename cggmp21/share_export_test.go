// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cggmp21

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// A struct field holding a secret is reached by every reflection encoder there
// is — json.Marshal, a %+v in a log line, a debug dump — and none of those call
// sites asks for key material. The signing session is handed back by the public
// API, and it carried both k_i and chi_i = x_i * k_i, so one printed value gave
// up the secret share to a single modular inverse.
//
// These names stay unexported. What may be exported is what the protocol already
// puts on the wire.
func TestNoExportedFieldHoldsASecret(t *testing.T) {
	secret := map[string]bool{
		"Xi": true, "Ki": true, "Gammai": true,
		"DeltaShare": true, "ChiShare": true,
		"Lambda": true, "Mu": true, "P": true, "Q": true,
	}

	fs := token.NewFileSet()
	pkgs, err := parser.ParseDir(fs, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, pkg := range pkgs {
		ast.Inspect(pkg, func(n ast.Node) bool {
			ts, ok := n.(*ast.TypeSpec)
			if !ok {
				return true
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return true
			}
			seen++
			for _, f := range st.Fields.List {
				for _, name := range f.Names {
					if secret[name.Name] {
						t.Errorf("%s.%s is exported and holds key material; every reflection encoder reaches it", ts.Name.Name, name.Name)
					}
					if !name.IsExported() && strings.Contains(strings.ToLower(name.Name), "share") {
						continue
					}
				}
			}
			return true
		})
	}
	if seen == 0 {
		t.Fatal("no structs parsed — this test has stopped covering the package")
	}
}
