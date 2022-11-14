package catalog

type Catalog map[string]string

var normalCatalog = Catalog{
	"* Starting tests!":  ":hammer_and_wrench: Starting tests!",
	"** Running go-ftw!": ":rocket:Running go-ftw!",
}

func Message(key string) string {
	text, ok := normalCatalog[key]
	if !ok {
		return ""
	}
	return text
}
