package droxo

import "strconv"

func GetPageData(pageData string) (int, int) {
	defaultPage := 1
	defaultSize := 10

	if len(pageData) < 2 {
		return defaultPage, defaultSize
	}

	pChar := []rune(pageData[:1])

	if len(pChar) != 1 {
		return defaultPage, defaultSize
	}

	page := int(pChar[0]) % 32
	pageSize, err := strconv.Atoi(pageData[1:])

	if err != nil {
		return defaultPage, defaultSize
	}

	return page, pageSize
}
