package quantitative

import (
	"fmt"

	"github.com/coreruleset/go-ftw/v2/internal/corpus"
	"github.com/coreruleset/go-ftw/v2/internal/quantitative/leipzig"
)

// CorpusFactory creates a new corpus
func CorpusFactory(t corpus.Type, corpusLocalPath string) (corpus.Corpus, error) {
	switch t {
	case corpus.Leipzig:
		return leipzig.NewLeipzigCorpus(corpusLocalPath), nil
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
