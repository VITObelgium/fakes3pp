package session

type AWSSessionTags struct {
	PrincipalTags     map[string][]string `json:"principal_tags"`
	TransitiveTagKeys []string            `json:"transitive_tag_keys,omitempty"`
}
