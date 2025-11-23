package quantitative

import (
	"fmt"

	"github.com/coreruleset/go-ftw/internal/corpus"
	"github.com/coreruleset/go-ftw/internal/quantitative/leipzig"
)

// CorpusFactory creates a new corpus
func CorpusFactory(t corpus.Type) (corpus.Corpus, error) {
	switch t {
	case corpus.Leipzig:
		return leipzig.NewLeipzigCorpus(), nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}

// PayloadFactory creates a new Payload based on the corpus.Type
func PayloadFactory(t corpus.Type) (corpus.Payload, error) {
	switch t {
	case corpus.Leipzig:
		return &leipzig.Payload{}, nil
	default:
		return nil, fmt.Errorf("unsupported corpus type: %s", t)
	}
}
