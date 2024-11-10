package requestutils

import "net/url"


func GetQueryParamsFromUrl(inputUrl string) (url.Values, error) {
	u, err := url.Parse(inputUrl)
    if err != nil {
        return nil, err
    }
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
        return nil, err
    }
	return q, nil
}