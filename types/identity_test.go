package types

import (
	"strings"
	"testing"
)

func TestServiceIdentityKeySerializationBoundary(t *testing.T) {
	t.Parallel()

	key := NewServiceIdentityKey(" Demo ", " 0xAbCd ")
	if got := key.String(); got != "demo:0xabcd" {
		t.Fatalf("ServiceIdentityKey.String() = %q, want demo:0xabcd", got)
	}
	parsed, err := ParseServiceIdentityKey(" Demo : 0xAbCd ")
	if err != nil {
		t.Fatal(err)
	}
	if parsed != key {
		t.Fatalf("ParseServiceIdentityKey() = %#v, want %#v", parsed, key)
	}
	if got, err := ParseIdentityKey(" Demo : 0xAbCd "); err != nil || got != key.String() {
		t.Fatalf("ParseIdentityKey() = %q, %v, want %q", got, err, key.String())
	}

	unnamedKey := NewServiceIdentityKey("", " 0xAbCd ")
	if got := unnamedKey.String(); got != ":0xabcd" {
		t.Fatalf("unnamed ServiceIdentityKey.String() = %q, want :0xabcd", got)
	}
	parsedUnnamed, err := ParseServiceIdentityKey(" : 0xAbCd ")
	if err != nil {
		t.Fatal(err)
	}
	if parsedUnnamed != unnamedKey {
		t.Fatalf("ParseServiceIdentityKey() = %#v, want %#v", parsedUnnamed, unnamedKey)
	}
	if got, err := ParseIdentityKey(" : 0xAbCd "); err != nil || got != unnamedKey.String() {
		t.Fatalf("ParseIdentityKey() = %q, %v, want %q", got, err, unnamedKey.String())
	}
}

func TestServiceIdentityKeyRejectsMalformedSerialization(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"", "demo", ":", "demo:", "demo:0x1:extra", ":0x1:extra"} {
		if _, err := ParseServiceIdentityKey(raw); err == nil {
			t.Errorf("ParseServiceIdentityKey(%q) error = nil", raw)
		}
	}
}

func TestLeaseMetadataValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		value   LeaseMetadata
		wantErr bool
	}{
		{"empty", LeaseMetadata{}, false},
		{"aggregate limit", LeaseMetadata{
			Description: strings.Repeat("d", LeaseMetadataMaxDescriptionBytes),
			Thumbnail:   strings.Repeat("t", LeaseMetadataMaxThumbnailBytes),
		}, false},
		{"description too long", LeaseMetadata{Description: strings.Repeat("d", LeaseMetadataMaxDescriptionBytes+1)}, true},
		{"owner too long", LeaseMetadata{Owner: strings.Repeat("o", LeaseMetadataMaxOwnerBytes+1)}, true},
		{"thumbnail too long", LeaseMetadata{Thumbnail: strings.Repeat("t", LeaseMetadataMaxThumbnailBytes+1)}, true},
		{"too many tags", LeaseMetadata{Tags: make([]string, LeaseMetadataMaxTags+1)}, true},
		{"tag too long in UTF-8 bytes", LeaseMetadata{Tags: []string{strings.Repeat("é", LeaseMetadataMaxTagBytes/2+1)}}, true},
		{"aggregate too large", LeaseMetadata{
			Description: strings.Repeat("d", LeaseMetadataMaxDescriptionBytes),
			Thumbnail:   strings.Repeat("t", LeaseMetadataMaxThumbnailBytes),
			Owner:       "x",
		}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.value.Validate()
			if (err != nil) != tt.wantErr {
				t.Fatalf("LeaseMetadata.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
