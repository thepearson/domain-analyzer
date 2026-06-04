package main

import (
	"reflect"
	"sort"
	"testing"
)

func TestIdentifyMailProviders(t *testing.T) {
	tests := []struct {
		name     string
		hosts    []string
		expected []string
	}{
		{
			name:     "Google Workspace",
			hosts:    []string{"aspmx.l.google.com.", "alt1.aspmx.l.google.com."},
			expected: []string{"Google Workspace"},
		},
		{
			name:     "Microsoft Outlook",
			hosts:    []string{"microsoft-com.mail.protection.outlook.com."},
			expected: []string{"Microsoft Outlook/Office 365"},
		},
		{
			name:     "Proton Mail",
			hosts:    []string{"mail.protonmail.ch.", "mailsec.protonmail.ch."},
			expected: []string{"Proton Mail"},
		},
		{
			name:     "Multiple Providers",
			hosts:    []string{"aspmx.l.google.com.", "mx.zoho.com."},
			expected: []string{"Google Workspace", "Zoho Mail"},
		},
		{
			name:     "Generic Provider",
			hosts:    []string{"mx1.example.com."},
			expected: []string{"Generic/Other (MX records found)"},
		},
		{
			name:     "No MX Records",
			hosts:    []string{},
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := identifyMailProviders(tt.hosts)
			sort.Strings(got)
			sort.Strings(tt.expected)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("identifyMailProviders() = %v, want %v", got, tt.expected)
			}
		})
	}
}
