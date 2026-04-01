package ed2ksrv

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"

	"github.com/monkeyWie/goed2k/protocol"
)

const (
	opLoginRequest     byte = 0x01
	opGetServerList    byte = 0x14
	opSearchRequest    byte = 0x16
	opGetSources       byte = 0x19
	opGetSourcesObfu   byte = 0x23 // OP_GETSOURCES_OBFU，与 OP_GETSOURCES 请求体相同，应答需用 OP_FOUNDSOURCES_OBFU
	opCallbackReq      byte = 0x1C
	opSearchMore       byte = 0x21
	opFoundSourcesObfu byte = 0x44 // OP_FOUNDSOURCES_OBFU，每源在 IP:端口后多 1 字节 crypt options
	searchTypeBool   byte = 0x00
	searchTypeString byte = 0x01
	searchTypeStrTag byte = 0x02
	searchTypeUint32 byte = 0x03
	searchTypeUint64 byte = 0x08

	searchOpEqual        byte = 0x00
	searchOpGreater      byte = 0x01
	searchOpLess         byte = 0x02
	searchOpGreaterEqual byte = 0x03
	searchOpLessEqual    byte = 0x04
	searchOpNotEqual     byte = 0x05

	searchBoolAnd    byte = 0x00
	searchBoolOr     byte = 0x01
	searchBoolAndNot byte = 0x02
	searchBoolXor    byte = 0x03
	searchBoolNotAnd byte = 0x04
)

// SearchQuery is the server-side view of an incoming ED2K search request.
type SearchQuery struct {
	Root               searchExpr
	Keywords           []string
	MinSize            int64
	MaxSize            int64
	MinSources         int
	MinCompleteSources int
	FileType           string
	Extension          string
	MediaCodec         string
	MinMediaLength     int
	MaxMediaLength     int
	MinMediaBitrate    int
	MaxMediaBitrate    int
}

type searchExpr interface {
	match(FileRecord) bool
	collectSummary(*SearchQuery) bool
}

type searchCompoundExpr struct {
	operator byte
	left     searchExpr
	right    searchExpr
}

type searchKeywordExpr struct {
	value string
}

type searchStringTagExpr struct {
	tagID byte
	value string
}

type searchNumericExpr struct {
	tagID    byte
	operator byte
	value    uint64
}

type searchMatchAllExpr struct{}

type searchMatchNoneExpr struct{}

type searchTagRef struct {
	id    byte
	name  string
	hasID bool
}

// ParseSearchRequest decodes ED2K search requests.
//
// It prefers Lugdunum-style recursive-prefix expressions and falls back to the
// legacy linear encoding currently emitted by the local goed2k helper.
func ParseSearchRequest(body []byte) (SearchQuery, error) {
	if len(body) == 0 {
		return SearchQuery{Root: searchMatchAllExpr{}}, nil
	}

	prefixQuery, prefixErr := parseRecursiveSearchRequest(body)
	if prefixErr == nil {
		return prefixQuery, nil
	}

	legacyQuery, legacyErr := parseLegacySearchRequest(body)
	if legacyErr == nil {
		return legacyQuery, nil
	}

	return SearchQuery{}, fmt.Errorf("parse recursive search: %v; parse legacy search: %v", prefixErr, legacyErr)
}

func parseRecursiveSearchRequest(body []byte) (SearchQuery, error) {
	reader := bytes.NewReader(body)
	root, err := parseRecursiveSearchExpr(reader)
	if err != nil {
		return SearchQuery{}, err
	}
	if reader.Len() != 0 {
		return SearchQuery{}, fmt.Errorf("unexpected trailing search payload: %d bytes", reader.Len())
	}
	return makeSearchQuery(root), nil
}

func parseRecursiveSearchExpr(reader *bytes.Reader) (searchExpr, error) {
	termType, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	switch termType {
	case searchTypeBool:
		operator, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		if operator > searchBoolNotAnd {
			return nil, fmt.Errorf("unsupported boolean operator: 0x%02x", operator)
		}
		left, err := parseRecursiveSearchExpr(reader)
		if err != nil {
			return nil, err
		}
		right, err := parseRecursiveSearchExpr(reader)
		if err != nil {
			return nil, err
		}
		return searchCompoundExpr{operator: operator, left: left, right: right}, nil
	case searchTypeString:
		value, err := readSearchString(reader)
		if err != nil {
			return nil, err
		}
		return makeKeywordExpr(value)
	case searchTypeStrTag:
		value, err := readSearchString(reader)
		if err != nil {
			return nil, err
		}
		tag, err := readSearchTagRef(reader)
		if err != nil {
			return nil, err
		}
		return makeStringTagExpr(value, tag)
	case searchTypeUint32:
		value, err := protocol.ReadUInt32(reader)
		if err != nil {
			return nil, err
		}
		return parseRecursiveNumericExpr(reader, uint64(value))
	case searchTypeUint64:
		value, err := protocol.ReadUInt64(reader)
		if err != nil {
			return nil, err
		}
		return parseRecursiveNumericExpr(reader, value)
	default:
		return nil, fmt.Errorf("unsupported search term type: 0x%02x", termType)
	}
}

func parseRecursiveNumericExpr(reader *bytes.Reader, value uint64) (searchExpr, error) {
	operator, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if operator > searchOpNotEqual {
		return nil, fmt.Errorf("unsupported numeric operator: 0x%02x", operator)
	}
	tag, err := readSearchTagRef(reader)
	if err != nil {
		return nil, err
	}
	return makeNumericTagExpr(value, operator, tag)
}

func parseLegacySearchRequest(body []byte) (SearchQuery, error) {
	reader := bytes.NewReader(body)
	root, err := parseLegacySearchTerm(reader)
	if err != nil {
		return SearchQuery{}, err
	}
	for reader.Len() > 0 {
		marker, err := reader.ReadByte()
		if err != nil {
			return SearchQuery{}, err
		}
		if marker != searchTypeBool {
			return SearchQuery{}, fmt.Errorf("unsupported legacy boolean marker: 0x%02x", marker)
		}
		operator, err := reader.ReadByte()
		if err != nil {
			return SearchQuery{}, err
		}
		if operator > searchBoolNotAnd {
			return SearchQuery{}, fmt.Errorf("unsupported legacy boolean operator: 0x%02x", operator)
		}
		next, err := parseLegacySearchTerm(reader)
		if err != nil {
			return SearchQuery{}, err
		}
		root = searchCompoundExpr{operator: operator, left: root, right: next}
	}
	return makeSearchQuery(root), nil
}

func parseLegacySearchTerm(reader *bytes.Reader) (searchExpr, error) {
	termType, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}

	switch termType {
	case searchTypeString:
		value, err := readSearchString(reader)
		if err != nil {
			return nil, err
		}
		return makeKeywordExpr(value)
	case searchTypeStrTag:
		value, err := readSearchString(reader)
		if err != nil {
			return nil, err
		}
		tagID, err := readLegacySearchTagID(reader)
		if err != nil {
			return nil, err
		}
		return makeStringTagExpr(value, searchTagRef{id: tagID, hasID: true})
	case searchTypeUint32:
		value, err := protocol.ReadUInt32(reader)
		if err != nil {
			return nil, err
		}
		return parseLegacyNumericExpr(reader, uint64(value))
	case searchTypeUint64:
		value, err := protocol.ReadUInt64(reader)
		if err != nil {
			return nil, err
		}
		return parseLegacyNumericExpr(reader, value)
	default:
		return nil, fmt.Errorf("unsupported legacy search term type: 0x%02x", termType)
	}
}

func parseLegacyNumericExpr(reader *bytes.Reader, value uint64) (searchExpr, error) {
	operator, err := reader.ReadByte()
	if err != nil {
		return nil, err
	}
	if operator > searchOpNotEqual {
		return nil, fmt.Errorf("unsupported numeric operator: 0x%02x", operator)
	}
	tagID, err := readLegacySearchTagID(reader)
	if err != nil {
		return nil, err
	}
	return makeNumericTagExpr(value, operator, searchTagRef{id: tagID, hasID: true})
}

func makeSearchQuery(root searchExpr) SearchQuery {
	query := SearchQuery{Root: root}
	if root != nil {
		root.collectSummary(&query)
	}
	return query
}

func makeKeywordExpr(value string) (searchExpr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return searchMatchAllExpr{}, nil
	}
	return searchKeywordExpr{value: value}, nil
}

func makeStringTagExpr(value string, tag searchTagRef) (searchExpr, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return searchMatchAllExpr{}, nil
	}

	switch {
	case tag.matchesID(protocol.FTFileType):
		return searchStringTagExpr{tagID: protocol.FTFileType, value: value}, nil
	case tag.matchesID(protocol.FTFileFormat):
		return searchStringTagExpr{tagID: protocol.FTFileFormat, value: value}, nil
	case tag.matchesID(protocol.FTMediaCodec), tag.matchesName("codec"):
		return searchStringTagExpr{tagID: protocol.FTMediaCodec, value: value}, nil
	case tag.matchesID(protocol.FTMediaLength), tag.matchesName("length"):
		seconds, err := parseMediaLength(value)
		if err != nil {
			return nil, fmt.Errorf("parse media length %q: %w", value, err)
		}
		return searchNumericExpr{tagID: protocol.FTMediaLength, operator: searchOpEqual, value: uint64(seconds)}, nil
	default:
		return nil, fmt.Errorf("unsupported string tag: %s", tag.describe())
	}
}

func makeNumericTagExpr(value uint64, operator byte, tag searchTagRef) (searchExpr, error) {
	switch {
	case tag.matchesID(protocol.FTFileSize):
		return searchNumericExpr{tagID: protocol.FTFileSize, operator: operator, value: value}, nil
	case tag.matchesID(protocol.FTSources):
		return searchNumericExpr{tagID: protocol.FTSources, operator: operator, value: value}, nil
	case tag.matchesID(protocol.FTCompleteSources):
		return searchNumericExpr{tagID: protocol.FTCompleteSources, operator: operator, value: value}, nil
	case tag.matchesID(protocol.FTMediaBitrate), tag.matchesName("bitrate"):
		return searchNumericExpr{tagID: protocol.FTMediaBitrate, operator: operator, value: value}, nil
	case tag.matchesID(protocol.FTMediaLength), tag.matchesName("length"):
		return searchNumericExpr{tagID: protocol.FTMediaLength, operator: operator, value: value}, nil
	default:
		return nil, fmt.Errorf("unsupported numeric tag: %s", tag.describe())
	}
}

func (q SearchQuery) match(record FileRecord) bool {
	if q.Root != nil {
		return q.Root.match(record)
	}
	return matchesLegacySearch(record, q)
}

func (e searchCompoundExpr) match(record FileRecord) bool {
	left := e.left.match(record)
	right := e.right.match(record)
	switch e.operator {
	case searchBoolAnd:
		return left && right
	case searchBoolOr:
		return left || right
	case searchBoolAndNot:
		return left && !right
	case searchBoolXor:
		return left != right
	case searchBoolNotAnd:
		return !left && right
	default:
		return false
	}
}

func (e searchCompoundExpr) collectSummary(query *SearchQuery) bool {
	if e.operator != searchBoolAnd {
		return false
	}
	leftOK := e.left.collectSummary(query)
	rightOK := e.right.collectSummary(query)
	return leftOK && rightOK
}

func (e searchKeywordExpr) match(record FileRecord) bool {
	return strings.Contains(strings.ToLower(record.Name), strings.ToLower(e.value))
}

func (e searchKeywordExpr) collectSummary(query *SearchQuery) bool {
	query.Keywords = append(query.Keywords, e.value)
	return true
}

func (e searchStringTagExpr) match(record FileRecord) bool {
	switch e.tagID {
	case protocol.FTFileType:
		return strings.EqualFold(record.FileType, e.value)
	case protocol.FTFileFormat:
		return strings.EqualFold(record.Extension, strings.TrimPrefix(e.value, "."))
	case protocol.FTMediaCodec:
		return strings.EqualFold(record.MediaCodec, e.value)
	default:
		return false
	}
}

func (e searchStringTagExpr) collectSummary(query *SearchQuery) bool {
	switch e.tagID {
	case protocol.FTFileType:
		query.FileType = e.value
	case protocol.FTFileFormat:
		query.Extension = strings.TrimPrefix(e.value, ".")
	case protocol.FTMediaCodec:
		query.MediaCodec = e.value
	default:
		return false
	}
	return true
}

func (e searchNumericExpr) match(record FileRecord) bool {
	switch e.tagID {
	case protocol.FTFileSize:
		return compareInt64(record.Size, e.operator, int64(e.value))
	case protocol.FTSources:
		return compareInt(record.Sources, e.operator, int(e.value))
	case protocol.FTCompleteSources:
		return compareInt(record.CompleteSources, e.operator, int(e.value))
	case protocol.FTMediaLength:
		return compareInt(record.MediaLength, e.operator, int(e.value))
	case protocol.FTMediaBitrate:
		return compareInt(record.MediaBitrate, e.operator, int(e.value))
	default:
		return false
	}
}

func (e searchNumericExpr) collectSummary(query *SearchQuery) bool {
	switch e.tagID {
	case protocol.FTFileSize:
		applyRangeInt64Summary(&query.MinSize, &query.MaxSize, e.operator, int64(e.value))
	case protocol.FTSources:
		applyMinIntSummary(&query.MinSources, e.operator, int(e.value))
	case protocol.FTCompleteSources:
		applyMinIntSummary(&query.MinCompleteSources, e.operator, int(e.value))
	case protocol.FTMediaLength:
		applyRangeIntSummary(&query.MinMediaLength, &query.MaxMediaLength, e.operator, int(e.value))
	case protocol.FTMediaBitrate:
		applyRangeIntSummary(&query.MinMediaBitrate, &query.MaxMediaBitrate, e.operator, int(e.value))
	default:
		return false
	}
	return true
}

func (searchMatchAllExpr) match(FileRecord) bool {
	return true
}

func (searchMatchAllExpr) collectSummary(*SearchQuery) bool {
	return true
}

func (searchMatchNoneExpr) match(FileRecord) bool {
	return false
}

func (searchMatchNoneExpr) collectSummary(*SearchQuery) bool {
	return false
}

func (t searchTagRef) matchesID(id byte) bool {
	return t.hasID && t.id == id
}

func (t searchTagRef) matchesName(name string) bool {
	return !t.hasID && strings.EqualFold(t.name, name)
}

func (t searchTagRef) describe() string {
	if t.hasID {
		return fmt.Sprintf("0x%02x", t.id)
	}
	return t.name
}

func readSearchString(reader *bytes.Reader) (string, error) {
	size, err := protocol.ReadUInt16(reader)
	if err != nil {
		return "", err
	}
	raw, err := protocol.ReadBytes(reader, int(size))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func readSearchTagRef(reader *bytes.Reader) (searchTagRef, error) {
	value, err := readSearchString(reader)
	if err != nil {
		return searchTagRef{}, err
	}
	if len(value) == 1 {
		return searchTagRef{id: value[0], hasID: true}, nil
	}
	if value == "" {
		return searchTagRef{}, fmt.Errorf("empty search tag")
	}
	return searchTagRef{name: value}, nil
}

func readLegacySearchTagID(reader *bytes.Reader) (byte, error) {
	tagCount, err := protocol.ReadUInt16(reader)
	if err != nil {
		return 0, err
	}
	if tagCount != 1 {
		return 0, fmt.Errorf("unsupported tag count: %d", tagCount)
	}
	return reader.ReadByte()
}

func compareInt64(left int64, operator byte, right int64) bool {
	switch operator {
	case searchOpEqual:
		return left == right
	case searchOpGreater:
		return left > right
	case searchOpLess:
		return left < right
	case searchOpGreaterEqual:
		return left >= right
	case searchOpLessEqual:
		return left <= right
	case searchOpNotEqual:
		return left != right
	default:
		return false
	}
}

func compareInt(left int, operator byte, right int) bool {
	switch operator {
	case searchOpEqual:
		return left == right
	case searchOpGreater:
		return left > right
	case searchOpLess:
		return left < right
	case searchOpGreaterEqual:
		return left >= right
	case searchOpLessEqual:
		return left <= right
	case searchOpNotEqual:
		return left != right
	default:
		return false
	}
}

func matchesLegacySearch(record FileRecord, query SearchQuery) bool {
	name := strings.ToLower(record.Name)
	if query.FileType != "" && !strings.EqualFold(record.FileType, query.FileType) {
		return false
	}
	if query.Extension != "" && !strings.EqualFold(record.Extension, strings.TrimPrefix(query.Extension, ".")) {
		return false
	}
	if query.MediaCodec != "" && !strings.EqualFold(record.MediaCodec, query.MediaCodec) {
		return false
	}
	if query.MinSize > 0 && record.Size < query.MinSize {
		return false
	}
	if query.MaxSize > 0 && record.Size > query.MaxSize {
		return false
	}
	if query.MinSources > 0 && record.Sources < query.MinSources {
		return false
	}
	if query.MinCompleteSources > 0 && record.CompleteSources < query.MinCompleteSources {
		return false
	}
	if query.MinMediaLength > 0 && record.MediaLength < query.MinMediaLength {
		return false
	}
	if query.MaxMediaLength > 0 && record.MediaLength > query.MaxMediaLength {
		return false
	}
	if query.MinMediaBitrate > 0 && record.MediaBitrate < query.MinMediaBitrate {
		return false
	}
	if query.MaxMediaBitrate > 0 && record.MediaBitrate > query.MaxMediaBitrate {
		return false
	}
	for _, keyword := range query.Keywords {
		if !strings.Contains(name, strings.ToLower(keyword)) {
			return false
		}
	}
	return true
}

func applyRangeInt64Summary(minValue, maxValue *int64, operator byte, value int64) {
	switch operator {
	case searchOpEqual:
		*minValue = value
		*maxValue = value
	case searchOpGreater, searchOpGreaterEqual:
		if *minValue == 0 || value > *minValue {
			*minValue = value
		}
	case searchOpLess, searchOpLessEqual:
		if *maxValue == 0 || value < *maxValue {
			*maxValue = value
		}
	}
}

func applyRangeIntSummary(minValue, maxValue *int, operator byte, value int) {
	switch operator {
	case searchOpEqual:
		*minValue = value
		*maxValue = value
	case searchOpGreater, searchOpGreaterEqual:
		if *minValue == 0 || value > *minValue {
			*minValue = value
		}
	case searchOpLess, searchOpLessEqual:
		if *maxValue == 0 || value < *maxValue {
			*maxValue = value
		}
	}
}

func applyMinIntSummary(minValue *int, operator byte, value int) {
	switch operator {
	case searchOpEqual, searchOpGreater, searchOpGreaterEqual:
		if value > *minValue {
			*minValue = value
		}
	}
}

func parseMediaLength(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, fmt.Errorf("empty length")
	}
	if !strings.Contains(value, ":") {
		seconds, err := strconv.Atoi(value)
		if err != nil {
			return 0, err
		}
		if seconds < 0 {
			return 0, fmt.Errorf("negative length")
		}
		return seconds, nil
	}

	parts := strings.Split(value, ":")
	if len(parts) < 2 || len(parts) > 3 {
		return 0, fmt.Errorf("invalid length format")
	}
	total := 0
	for _, part := range parts {
		number, err := strconv.Atoi(part)
		if err != nil {
			return 0, err
		}
		if number < 0 {
			return 0, fmt.Errorf("negative length component")
		}
		total = total*60 + number
	}
	return total, nil
}
