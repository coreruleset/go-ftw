package leipzig

import "bufio"

type LeipzigIterator struct {
	scanner *bufio.Scanner
}

// HasNext returns true if there is another sentence in the corpus
func (c *LeipzigIterator) HasNext() bool {
	return c.scanner.Scan()
}

// Next returns the next sentence from the corpus
func (c *LeipzigIterator) Next() string {
	return c.scanner.Text()
}
