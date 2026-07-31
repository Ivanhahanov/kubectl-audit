package loader

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

var manifestExt = map[string]bool{
	".yaml": true,
	".yml":  true,
	".json": true,
}

// LoadStatic reads Kubernetes manifests from a mix of files and directories.
// Directories are walked recursively; multi-document YAML files are split
// into individual resources. Empty documents and documents without a Kind
// are skipped.
func LoadStatic(paths []string) ([]Resource, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("static manifest path %s: %w", p, err)
		}
		if info.IsDir() {
			err := filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				if manifestExt[strings.ToLower(filepath.Ext(path))] {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, fmt.Errorf("walking %s: %w", p, err)
			}
		} else {
			files = append(files, p)
		}
	}

	var out []Resource
	for _, f := range files {
		resources, err := loadFile(f)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", f, err)
		}
		out = append(out, resources...)
	}
	return out, nil
}

func loadFile(path string) ([]Resource, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	dec := k8syaml.NewYAMLOrJSONDecoder(bufio.NewReader(f), 4096)
	var out []Resource
	for {
		var raw map[string]interface{}
		if err := dec.Decode(&raw); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		if len(raw) == 0 {
			continue
		}
		u := &unstructured.Unstructured{Object: raw}
		if u.GetKind() == "" || u.GetAPIVersion() == "" {
			continue
		}
		// Skip List-kind wrappers by flattening their items.
		if strings.HasSuffix(u.GetKind(), "List") {
			items, found, _ := unstructured.NestedSlice(raw, "items")
			if found {
				for _, item := range items {
					m, ok := item.(map[string]interface{})
					if !ok {
						continue
					}
					iu := &unstructured.Unstructured{Object: m}
					if iu.GetKind() == "" {
						continue
					}
					out = append(out, Resource{Object: iu, Source: path})
				}
				continue
			}
		}
		out = append(out, Resource{Object: u, Source: path})
	}
	return out, nil
}
