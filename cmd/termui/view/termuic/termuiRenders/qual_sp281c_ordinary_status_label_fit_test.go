package termuiRenders

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryStatusLabelFit(t *testing.T) {
	t.Parallel()

	// Synthetic ASCII labels only; no widgets or terminal are initialized.
	cases := []struct {
		name  string
		label string
		width int
		want  string
	}{
		{name: "wide pane retains label", label: "sample", width: 12, want: "sample"},
		{name: "compact pane adds ellipsis", label: "sample-label", width: 10, want: "sampl..."},
		{name: "minimum pane leaves label blank", label: "sample-label", width: 5, want: ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tc.want, fitStringToWidth(tc.label, tc.width))
		})
	}
}
