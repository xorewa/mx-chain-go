package termuiRenders

import (
	"image"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestQualSP281COrdinaryDrawableContainerSparseResize(t *testing.T) {
	t.Parallel()

	container := NewDrawableContainer()
	right := &ordinaryDrawableStub{}
	container.SetTopRight(right)

	container.SetRectangle(2, 3, 81, 48)
	require.Equal(t, image.Rect(40, 3, 81, 24), right.GetRect())

	container.SetRectangle(4, 5, 100, 60)
	require.Equal(t, image.Rect(50, 5, 100, 24), right.GetRect())

	items := container.Items()
	require.Len(t, items, 3)
	require.Nil(t, items[0])
	require.Same(t, right, items[1])
	require.Nil(t, items[2])
}
