package plugin

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	defaultPathColumn  = "path"
	defaultKeyColumn   = "key"
	defaultValueColumn = "value"
)

const (
	writeModePut   = "put"
	writeModePatch = "patch"
)

type csvImportMode string

const (
	csvImportModeRow csvImportMode = "row-paths"
	csvImportModeKV  csvImportMode = "fixed-secret"
)

type csvImportRequest struct {
	CSV             string
	Delimiter       string
	BasePath        string
	PathColumn      string
	SecretPath      string
	KeyColumn       string
	ValueColumn     string
	SkipEmptyValues bool
	TrimSpace       bool
}

type csvWrite struct {
	Path string
	Data map[string]interface{}
}

type csvImportResult struct {
	Mode      csvImportMode
	TotalRows int
	Writes    []csvWrite
}

func buildWritesFromCSV(req csvImportRequest) (*csvImportResult, error) {
	delimiter, err := parseDelimiter(req.Delimiter)
	if err != nil {
		return nil, err
	}

	headers, rows, err := parseCSV(req.CSV, delimiter)
	if err != nil {
		return nil, err
	}

	if len(headers) == 0 {
		return nil, fmt.Errorf("csv header row is required")
	}

	if req.TrimSpace {
		for i := range headers {
			headers[i] = strings.TrimSpace(headers[i])
		}
	}
	headers[0] = strings.TrimPrefix(headers[0], "\ufeff")

	if req.SecretPath != "" {
		return buildFixedSecretWrites(headers, rows, req)
	}

	return buildRowPathWrites(headers, rows, req)
}

func buildRowPathWrites(headers []string, rows [][]string, req csvImportRequest) (*csvImportResult, error) {
	pathColumn := defaultString(req.PathColumn, defaultPathColumn)
	pathIndex, err := findHeaderIndex(headers, pathColumn)
	if err != nil {
		return nil, err
	}

	writes := make([]csvWrite, 0, len(rows))
	seenPaths := make(map[string]int, len(rows))
	for idx, row := range rows {
		if rowIsEmpty(row, req.TrimSpace) {
			continue
		}

		rowNumber := idx + 2
		if pathIndex >= len(row) {
			return nil, fmt.Errorf("row %d is missing the %q column", rowNumber, pathColumn)
		}

		secretPath := cellValue(row[pathIndex], req.TrimSpace)
		if secretPath == "" {
			return nil, fmt.Errorf("row %d has an empty %q value", rowNumber, pathColumn)
		}

		data := map[string]interface{}{}
		for colIdx, header := range headers {
			if colIdx == pathIndex {
				continue
			}
			if strings.TrimSpace(header) == "" {
				continue
			}

			value := ""
			if colIdx < len(row) {
				value = cellValue(row[colIdx], req.TrimSpace)
			}

			if req.SkipEmptyValues && value == "" {
				continue
			}

			data[header] = value
		}

		if len(data) == 0 {
			return nil, fmt.Errorf("row %d did not contain any secret fields", rowNumber)
		}

		finalPath := joinSecretPath(req.BasePath, secretPath)
		if previousRow, exists := seenPaths[finalPath]; exists {
			return nil, fmt.Errorf("row %d reuses secret path %q already used by row %d", rowNumber, finalPath, previousRow)
		}
		seenPaths[finalPath] = rowNumber

		writes = append(writes, csvWrite{
			Path: finalPath,
			Data: data,
		})
	}

	if len(writes) == 0 {
		return nil, fmt.Errorf("csv did not contain any importable rows")
	}

	return &csvImportResult{
		Mode:      csvImportModeRow,
		TotalRows: len(rows),
		Writes:    writes,
	}, nil
}

func buildFixedSecretWrites(headers []string, rows [][]string, req csvImportRequest) (*csvImportResult, error) {
	keyColumn := defaultString(req.KeyColumn, defaultKeyColumn)
	valueColumn := defaultString(req.ValueColumn, defaultValueColumn)

	keyIndex, err := findHeaderIndex(headers, keyColumn)
	if err != nil {
		return nil, err
	}

	valueIndex, err := findHeaderIndex(headers, valueColumn)
	if err != nil {
		return nil, err
	}

	data := map[string]interface{}{}
	for idx, row := range rows {
		if rowIsEmpty(row, req.TrimSpace) {
			continue
		}

		rowNumber := idx + 2
		if keyIndex >= len(row) || valueIndex >= len(row) {
			return nil, fmt.Errorf("row %d is missing the %q or %q column", rowNumber, keyColumn, valueColumn)
		}

		key := cellValue(row[keyIndex], req.TrimSpace)
		value := cellValue(row[valueIndex], req.TrimSpace)

		if key == "" && value == "" {
			continue
		}
		if key == "" {
			return nil, fmt.Errorf("row %d has an empty %q value", rowNumber, keyColumn)
		}
		if req.SkipEmptyValues && value == "" {
			continue
		}
		if _, exists := data[key]; exists {
			return nil, fmt.Errorf("row %d reuses key %q", rowNumber, key)
		}

		data[key] = value
	}

	if len(data) == 0 {
		return nil, fmt.Errorf("csv did not contain any key/value pairs to import")
	}

	return &csvImportResult{
		Mode:      csvImportModeKV,
		TotalRows: len(rows),
		Writes: []csvWrite{
			{
				Path: joinSecretPath(req.BasePath, req.SecretPath),
				Data: data,
			},
		},
	}, nil
}

func parseCSV(input string, delimiter rune) ([]string, [][]string, error) {
	reader := csv.NewReader(strings.NewReader(input))
	reader.Comma = delimiter
	reader.FieldsPerRecord = -1
	reader.TrimLeadingSpace = false

	headers, err := reader.Read()
	if err != nil {
		if err == io.EOF {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read csv header: %w", err)
	}

	rows := make([][]string, 0)
	for {
		record, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("read csv row: %w", err)
		}

		rows = append(rows, record)
	}

	return headers, rows, nil
}

func parseDelimiter(input string) (rune, error) {
	if strings.TrimSpace(input) == "" {
		return ',', nil
	}
	if utf8.RuneCountInString(input) != 1 {
		return 0, fmt.Errorf("delimiter must be a single character")
	}

	delimiter, _ := utf8.DecodeRuneInString(input)
	return delimiter, nil
}

func findHeaderIndex(headers []string, name string) (int, error) {
	want := strings.ToLower(strings.TrimSpace(name))
	for idx, header := range headers {
		if strings.ToLower(strings.TrimSpace(header)) == want {
			return idx, nil
		}
	}

	return -1, fmt.Errorf("csv is missing required column %q", name)
}

func rowIsEmpty(row []string, trimSpace bool) bool {
	for _, value := range row {
		if cellValue(value, trimSpace) != "" {
			return false
		}
	}

	return true
}

func cellValue(value string, trimSpace bool) string {
	if trimSpace {
		return strings.TrimSpace(value)
	}

	return value
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}

	return strings.TrimSpace(value)
}

func joinSecretPath(basePath, secretPath string) string {
	base := strings.Trim(strings.TrimSpace(basePath), "/")
	path := strings.Trim(strings.TrimSpace(secretPath), "/")

	switch {
	case base == "":
		return path
	case path == "":
		return base
	default:
		return base + "/" + path
	}
}

func cleanNamespace(namespace string) string {
	return strings.Trim(strings.TrimSpace(namespace), "/")
}

func normalizeWriteMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "", writeModePut:
		return writeModePut
	case writeModePatch:
		return writeModePatch
	default:
		return ""
	}
}
