package termuiRenders

import (
	"image"
	"sync"
	"testing"

	"github.com/gizak/termui/v3"
	"github.com/stretchr/testify/require"
)

type ordinaryDrawableStub struct {
	sync.Mutex
	rect image.Rectangle
}

func (d *ordinaryDrawableStub) GetRect() image.Rectangle {
	return d.rect
}

func (d *ordinaryDrawableStub) SetRect(x1, y1, x2, y2 int) {
	d.rect = image.Rect(x1, y1, x2, y2)
}

func (d *ordinaryDrawableStub) Draw(*termui.Buffer) {}

var _ termui.Drawable = (*ordinaryDrawableStub)(nil)

func TestQualSP281COrdinaryDrawableContainerLayout(t *testing.T) {
	t.Parallel()

	container := NewDrawableContainer()
	require.Nil(t, container.TopLeft())
	require.Nil(t, container.TopRight())
	require.Nil(t, container.Bottom())
	require.Equal(t, []termui.Drawable{nil, nil, nil}, container.Items())

	left := &ordinaryDrawableStub{}
	right := &ordinaryDrawableStub{}
	bottom := &ordinaryDrawableStub{}
	container.SetTopLeft(left)
	container.SetTopRight(right)
	container.SetBottom(bottom)

	require.Same(t, left, container.TopLeft())
	require.Same(t, right, container.TopRight())
	require.Same(t, bottom, container.Bottom())
	items := container.Items()
	require.Len(t, items, 3)
	require.Same(t, left, items[0])
	require.Same(t, right, items[1])
	require.Same(t, bottom, items[2])

	container.SetRectangle(2, 3, 80, 48)
	require.Equal(t, image.Rect(2, 3, 40, 24), left.GetRect())
	require.Equal(t, image.Rect(40, 3, 80, 24), right.GetRect())
	require.Equal(t, image.Rect(2, 24, 80, 48), bottom.GetRect())
}
