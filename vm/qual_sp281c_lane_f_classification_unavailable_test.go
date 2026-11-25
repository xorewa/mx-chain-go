package vm

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281CLaneFClassificationUnavailablePreservesCause(t *testing.T) {
	cause := errors.New("fixture read dependency unavailable")
	unavailable := NewDRWAClassificationUnavailable(cause)

	require.ErrorContains(t, unavailable, cause.Error())
	require.ErrorContains(t, unavailable, ErrDRWAExecution.Error())
	require.Same(t, cause, errors.Unwrap(unavailable))
	require.ErrorIs(t, unavailable, cause)
	require.ErrorIs(t, unavailable, ErrDRWAExecution)
	require.NotErrorIs(t, unavailable, errors.New(cause.Error()))
}

func TestQualSP281CLaneFClassificationUnavailableDirectOnly(t *testing.T) {
	cause := errors.New("fixture read dependency unavailable")
	unavailable := NewDRWAClassificationUnavailable(cause)
	additional := errors.New("fixture secondary failure")
	wrapped := fmt.Errorf("fixture boundary: %w", unavailable)
	joined := errors.Join(unavailable, additional)

	for _, test := range []struct {
		name string
		err  error
		want bool
	}{
		{name: "direct", err: unavailable, want: true},
		{name: "wrapped", err: wrapped},
		{name: "joined", err: joined},
		{name: "bare execution marker", err: ErrDRWAExecution},
		{name: "ordinary cause", err: cause},
		{name: "same diagnostic only", err: errors.New(unavailable.Error())},
		{name: "nil"},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.want, IsDirectDRWAClassificationUnavailable(test.err))
		})
	}

	for _, err := range []error{wrapped, joined} {
		require.ErrorIs(t, err, ErrDRWAExecution)
		require.ErrorIs(t, err, cause)
	}
	require.ErrorIs(t, joined, additional)
}
