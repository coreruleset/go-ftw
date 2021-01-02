package utils

// IsNotEmpty helper that returns true when a type is not empty
func IsNotEmpty(data interface{}) bool {
	return !IsEmpty(data)
}

// IsEmpty helper that returns true when a type is empty
func IsEmpty(data interface{}) bool {
	switch data := data.(type) {
	case string:
		if data == "" {
			return true
		}
		return false
	case []byte:
		if len(data) == 0 {
			return true
		}
		return false
	default:
		return false
	}
}
