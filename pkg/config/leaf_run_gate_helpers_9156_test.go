package config

import (
	"os"
	"path/filepath"
)

func filepathGlob9156(pat string) ([]string, error) {
	return filepath.Glob(pat)
}

func readFile9156(p string) (string, error) {
	b, err := os.ReadFile(p)
	return string(b), err
}
