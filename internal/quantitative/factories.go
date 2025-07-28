package quantitative

import (
	"fmt"

	"github.com/coreruleset/go-ftw/internal/corpus"
	"github.com/coreruleset/go-ftw/internal/quantitative/leipzig"
	"github.com/coreruleset/go-ftw/internal/quantitative/raw"
)

// CorpusFactory creates a new corpus
func CorpusFactory(t corpus.Type, corpusLocalPath string) (corpus.Corpus, error) {
	switch t {
	case corpus.Leipzig:
		return leipzig.NewLeipzigCorpus(corpusLocalPath), nil
	case corpus.Raw:
		return raw.NewRawCorpus(), nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}

// PayloadFactory creates a new Payload based on the corpus.Type
func PayloadFactory(t corpus.Type) (corpus.Payload, error) {
	switch t {
	case corpus.Leipzig:
		return &leipzig.Payload{}, nil
	case corpus.Raw:
		return &raw.Payload{}, nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}
