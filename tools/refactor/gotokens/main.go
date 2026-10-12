//
// OpenMCX Licence Information : AGPL-3.0-or-later
//

// Command gotokens proves that edits to Go files changed no code: it compares the token
// streams of two versions of a file, ignoring comments, and allows identifiers (renamed
// variables, parameters, receivers) to differ; every keyword, operator and literal must match.
//
//	gotokens BEFORE AFTER
package main

import (
	"fmt"
	"go/scanner"
	"go/token"
	"os"
)

//------------------------------------------------------------------------------
// Helper: the tokens of a file, comments left out, with their literal text.
func tokens(path string) ([]token.Token, []string, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	fileSet := token.NewFileSet()
	file := fileSet.AddFile(path, fileSet.Base(), len(source))
	var reader scanner.Scanner
	reader.Init(file, source, nil, 0)
	var kinds []token.Token
	var texts []string
	for {
		_, kind, literal := reader.Scan()
		if kind == token.EOF {
			return kinds, texts, nil
		}
		// Comments, and the semicolons the scanner inserts at line ends, are layout, not code.
		if kind == token.COMMENT || (kind == token.SEMICOLON && literal == "\n") {
			continue
		}
		kinds = append(kinds, kind)
		texts = append(texts, literal)
	}
}

//------------------------------------------------------------------------------
// Helper: compares the two files and reports the first difference that is not a renamed identifier.
func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: gotokens BEFORE AFTER")
		os.Exit(2)
	}
	beforeKinds, beforeTexts, err := tokens(os.Args[1])
	if err == nil {
		var afterKinds []token.Token
		var afterTexts []string
		afterKinds, afterTexts, err = tokens(os.Args[2])
		if err == nil {
			if len(beforeKinds) != len(afterKinds) {
				fmt.Printf("%s: CODE CHANGED (%d tokens, was %d)\n", os.Args[2], len(afterKinds), len(beforeKinds))
				os.Exit(1)
			}
			for index := range beforeKinds {
				if beforeKinds[index] != afterKinds[index] ||
					(beforeKinds[index] != token.IDENT && beforeTexts[index] != afterTexts[index]) {
					fmt.Printf("%s: CODE CHANGED at token %d: %q became %q\n", os.Args[2], index, beforeTexts[index], afterTexts[index])
					os.Exit(1)
				}
			}
			fmt.Printf("%s: same code (identifiers renamed only)\n", os.Args[2])
			return
		}
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(2)
}
